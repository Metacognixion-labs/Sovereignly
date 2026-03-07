/**
 * SovereignAuth  Passkeys (WebAuthn / FIDO2)
 *
 * Server-side WebAuthn implementation. Zero external dependencies.
 * Uses only Web Crypto API (already in Bun) + minimal CBOR decoding.
 *
 * WHY PASSKEYS OVER EMAIL OTP:
 *   - Zero SMTP dependency  no external delivery service
 *   - Biometric (FaceID, TouchID, Windows Hello, YubiKey)
 *   - Phishing-IMPOSSIBLE  credentials are domain-bound by spec
 *   - NIST 800-63B AAL2/AAL3 compliant
 *   - Satisfies SOC2 CC6.1 (multi-factor authentication)
 *   - Every modern device supports it (iOS 16+, Android 9+, Windows 10+)
 *
 * FLOW:
 *   Registration:
 *     1. GET  /auth/passkeys/register/begin     server issues challenge + options
 *     2. frontend: navigator.credentials.create(options)  attestation
 *     3. POST /auth/passkeys/register/complete  server verifies + stores credential
 *
 *   Authentication:
 *     1. GET  /auth/passkeys/login/begin        server issues challenge
 *     2. frontend: navigator.credentials.get(options)  assertion
 *     3. POST /auth/passkeys/login/complete     server verifies + issues JWT
 *
 * STORAGE: Credentials stored in per-tenant SQLite (bun:sqlite, already our dep)
 */

import { Database }  from "bun:sqlite";
import { join }      from "node:path";
import { sha256Raw } from "../security/crypto.ts";

//  Types 

export interface PasskeyCredential {
  id:              string;    // base64url credential ID
  userId:          string;    // our internal user ID
  publicKeyJwk:    string;    // JSON-serialized JWK public key (COSE decoded)
  counter:         number;    // signature counter (replay protection)
  aaguid:          string;    // authenticator AAGUID (device type)
  transports?:     string[];  // ["internal", "hybrid", "usb", "nfc", "ble"]
  createdAt:       number;
  lastUsedAt:      number;
  deviceName?:     string;    // user-assigned device label
}

export interface RegistrationBeginResult {
  challenge:    string;   // base64url
  userId:       string;   // base64url encoded internal user ID
  userName:     string;
  userDisplayName: string;
  rpId:         string;   // relying party domain
  rpName:       string;
  timeout:      number;
  // Full PublicKeyCredentialCreationOptions for navigator.credentials.create()
  options:      object;
}

export interface AuthBeginResult {
  challenge: string;
  rpId:      string;
  timeout:   number;
  options:   object;
}

//  CBOR decoder (minimal  only what WebAuthn uses) 
// WebAuthn attestation objects and authenticator data use CBOR encoding.
// We decode only the subset required. No external CBOR library needed.

class CBORDecoder {
  private pos = 0;
  constructor(private data: Uint8Array) {}

  decode(): any {
    const ib = this.data[this.pos++];
    const mt = (ib & 0xe0) >> 5;  // major type
    const ai = ib & 0x1f;          // additional info

    const len = this.readLen(ai);

    switch (mt) {
      case 0: return len;                          // unsigned int
      case 1: return -1 - len;                     // negative int
      case 2: return this.readBytes(len);           // bytes
      case 3: return this.readString(len);          // text string
      case 4: return Array.from({ length: len }, () => this.decode()); // array
      case 5: {                                     // map
        const obj: Record<any, any> = {};
        for (let i = 0; i < len; i++) {
          const k = this.decode();
          obj[k] = this.decode();
        }
        return obj;
      }
      case 6: return this.decode();                 // tag  skip, decode value
      case 7: {
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 27) {
          // 64-bit float
          const view = new DataView(this.data.buffer, this.pos);
          this.pos += 8;
          return view.getFloat64(0, false);
        }
        return undefined;
      }
      default: throw new Error(`Unsupported CBOR major type: ${mt}`);
    }
  }

  private readLen(ai: number): number {
    if (ai < 24) return ai;
    if (ai === 24) return this.data[this.pos++];
    if (ai === 25) { const v = (this.data[this.pos] << 8) | this.data[this.pos + 1]; this.pos += 2; return v; }
    if (ai === 26) { const v = new DataView(this.data.buffer, this.pos).getUint32(0, false); this.pos += 4; return v; }
    throw new Error(`Unsupported CBOR additional info: ${ai}`);
  }

  private readBytes(len: number): Uint8Array {
    const bytes = this.data.slice(this.pos, this.pos + len);
    this.pos += len;
    return bytes;
  }

  private readString(len: number): string {
    const bytes = this.readBytes(len);
    return new TextDecoder().decode(bytes);
  }
}

function cborDecode(data: Uint8Array): any {
  return new CBORDecoder(data).decode();
}

//  Base64url helpers 

function b64urlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded  = base64 + "==".slice((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

//  COSE key  JWK conversion 
// Authenticators return public keys in COSE format (RFC 8152).
// We convert to JWK for storage and Web Crypto import.

async function coseToJwk(coseKey: Record<number, any>): Promise<JsonWebKey> {
  const kty = coseKey[1];  // Key Type: 2=EC, 3=RSA, 1=OKP
  const alg = coseKey[3];  // Algorithm: -7=ES256, -257=RS256, -8=EdDSA

  if (kty === 2 && alg === -7) {
    // EC P-256 (ES256)  most common for platform authenticators
    return {
      kty: "EC",
      crv: "P-256",
      x: b64urlEncode(coseKey[-2]),
      y: b64urlEncode(coseKey[-3]),
      alg: "ES256",
    };
  }

  if (kty === 2 && alg === -35) {
    // EC P-384 (ES384)
    return {
      kty: "EC",
      crv: "P-384",
      x: b64urlEncode(coseKey[-2]),
      y: b64urlEncode(coseKey[-3]),
      alg: "ES384",
    };
  }

  if (kty === 1 && alg === -8) {
    // OKP Ed25519 (EdDSA)  YubiKey 5 series
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: b64urlEncode(coseKey[-2]),
      alg: "EdDSA",
    };
  }

  if (kty === 3 && alg === -257) {
    // RSA (RS256)  legacy Windows Hello
    return {
      kty: "RSA",
      alg: "RS256",
      n: b64urlEncode(coseKey[-1]),
      e: b64urlEncode(coseKey[-2]),
    };
  }

  throw new Error(`Unsupported COSE key type: kty=${kty} alg=${alg}`);
}

//  Import JWK for signature verification 

async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  if (jwk.kty === "EC") {
    return crypto.subtle.importKey(
      "jwk", jwk,
      { name: "ECDSA", namedCurve: jwk.crv! },
      false, ["verify"]
    );
  }
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    return crypto.subtle.importKey(
      "jwk", jwk,
      { name: "Ed25519" },
      false, ["verify"]
    );
  }
  if (jwk.kty === "RSA") {
    return crypto.subtle.importKey(
      "jwk", jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false, ["verify"]
    );
  }
  throw new Error(`Cannot import key type: ${jwk.kty}`);
}

//  PasskeyEngine 

export class PasskeyEngine {
  private db:      Database;
  private rpId:    string;
  private rpName:  string;
  private origin:  string;
  private challenges = new Map<string, { userId: string; expiresAt: number; type: "reg" | "auth" }>();

  constructor(opts: {
    dataDir: string;
    rpId:    string;    // domain e.g. "app.sovereignly.io"
    rpName:  string;    // display name e.g. "Sovereignly"
    origin:  string;    // full origin e.g. "https://app.sovereignly.io"
  }) {
    this.rpId   = opts.rpId;
    this.rpName = opts.rpName;
    this.origin = opts.origin;
    this.db     = new Database(join(opts.dataDir, "passkeys.db"));
    this.initSchema();
  }

  private initSchema() {
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run(`
      CREATE TABLE IF NOT EXISTS credentials (
        id              TEXT PRIMARY KEY,
        user_id         TEXT NOT NULL,
        public_key_jwk  TEXT NOT NULL,
        counter         INTEGER NOT NULL DEFAULT 0,
        aaguid          TEXT,
        transports      TEXT,
        device_name     TEXT,
        created_at      INTEGER NOT NULL,
        last_used_at    INTEGER NOT NULL
      )
    `);
    this.db.run("CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(user_id)");
  }

  //  REGISTRATION 

  beginRegistration(opts: {
    userId:       string;
    userName:     string;
    displayName:  string;
    existingCredentials?: string[];  // existing cred IDs to exclude
  }): RegistrationBeginResult {
    const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const userIdB64 = b64urlEncode(new TextEncoder().encode(opts.userId));

    this.challenges.set(challenge, {
      userId: opts.userId,
      expiresAt: Date.now() + 5 * 60 * 1000,  // 5 min
      type: "reg",
    });

    const options = {
      rp: { id: this.rpId, name: this.rpName },
      user: {
        id: userIdB64,
        name: opts.userName,
        displayName: opts.displayName,
      },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -7   },   // ES256 (P-256)  preferred
        { type: "public-key", alg: -8   },   // EdDSA (Ed25519)
        { type: "public-key", alg: -35  },   // ES384
        { type: "public-key", alg: -257 },   // RS256 (legacy fallback)
      ],
      timeout: 300_000,  // 5 minutes
      attestation: "none",  // "none" = no device attestation needed, max compatibility
      authenticatorSelection: {
        residentKey:        "required",   // passkey requirement
        requireResidentKey: true,
        userVerification:   "required",   // biometric required
      },
      excludeCredentials: (opts.existingCredentials ?? []).map(id => ({
        type: "public-key",
        id,
        transports: ["internal", "hybrid"],
      })),
    };

    return {
      challenge, userId: userIdB64,
      userName: opts.userName, userDisplayName: opts.displayName,
      rpId: this.rpId, rpName: this.rpName, timeout: 300_000, options,
    };
  }

  async completeRegistration(opts: {
    challenge:         string;
    credentialId:      string;   // base64url
    attestationObject: string;   // base64url CBOR
    clientDataJSON:    string;   // base64url JSON
    transports?:       string[];
    deviceName?:       string;
  }): Promise<{ ok: boolean; credentialId?: string; reason?: string }> {
    try {
      // 1. Verify challenge
      const ch = this.challenges.get(opts.challenge);
      if (!ch || ch.type !== "reg") return { ok: false, reason: "invalid challenge" };
      if (Date.now() > ch.expiresAt)  return { ok: false, reason: "challenge expired" };
      this.challenges.delete(opts.challenge);

      // 2. Verify clientDataJSON
      const clientData = JSON.parse(new TextDecoder().decode(b64urlDecode(opts.clientDataJSON)));
      if (clientData.type !== "webauthn.create") return { ok: false, reason: "wrong type" };
      if (clientData.challenge !== opts.challenge) return { ok: false, reason: "challenge mismatch" };
      if (!clientData.origin.startsWith(this.origin)) return { ok: false, reason: "origin mismatch" };

      // 3. Decode attestation object (CBOR)
      const attObj = cborDecode(b64urlDecode(opts.attestationObject));
      const authData: Uint8Array = attObj.authData;

      // 4. Parse authenticator data
      // rpIdHash (32) | flags (1) | counter (4) | aaguid (16) | credIdLen (2) | credId | coseKey
      const rpIdHash = authData.slice(0, 32);
      const flags    = authData[32];
      const counter  = new DataView(authData.buffer, authData.byteOffset + 33).getUint32(0, false);

      // Verify RP ID hash
      const expectedRpIdHash = await sha256Raw(this.rpId);
      if (!timingSafeEqual(rpIdHash, expectedRpIdHash)) {
        return { ok: false, reason: "rpId hash mismatch" };
      }

      // Verify flags: UP (user present) + UV (user verified) must be set
      const UP = (flags & 0x01) !== 0;
      const UV = (flags & 0x04) !== 0;
      if (!UP) return { ok: false, reason: "user presence not confirmed" };
      if (!UV) return { ok: false, reason: "user verification not confirmed (biometric required)" };

      // Check attested credential data present (AT flag)
      const AT = (flags & 0x40) !== 0;
      if (!AT) return { ok: false, reason: "no attested credential data" };

      // Parse credential ID
      let offset = 37;
      const aaguidBytes  = authData.slice(offset, offset + 16); offset += 16;
      const credIdLen    = new DataView(authData.buffer, authData.byteOffset + offset).getUint16(0, false); offset += 2;
      const credIdBytes  = authData.slice(offset, offset + credIdLen); offset += credIdLen;
      const credId       = b64urlEncode(credIdBytes);

      // Parse COSE public key
      const coseKeyBytes = authData.slice(offset);
      const coseKey      = cborDecode(coseKeyBytes);
      const jwk          = await coseToJwk(coseKey);

      // 5. Check credential ID matches what browser returned
      if (credId !== opts.credentialId) {
        return { ok: false, reason: "credential ID mismatch" };
      }

      // 6. Store credential
      const now = Date.now();
      const aaguid = b64urlEncode(aaguidBytes);

      this.db.prepare(`
        INSERT OR REPLACE INTO credentials
          (id, user_id, public_key_jwk, counter, aaguid, transports, device_name, created_at, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        credId, ch.userId, JSON.stringify(jwk), counter, aaguid,
        JSON.stringify(opts.transports ?? []),
        opts.deviceName ?? this.guessDeviceName(aaguid, opts.transports ?? []),
        now, now
      );

      return { ok: true, credentialId: credId };
    } catch (err: any) {
      return { ok: false, reason: err.message };
    }
  }

  //  AUTHENTICATION 

  beginAuthentication(opts: {
    userId?:       string;   // optional  if absent, any registered key works
    credentialIds?: string[];
  }): AuthBeginResult {
    const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));

    this.challenges.set(challenge, {
      userId: opts.userId ?? "__any__",
      expiresAt: Date.now() + 5 * 60 * 1000,
      type: "auth",
    });

    const allowCredentials = opts.credentialIds?.map(id => ({
      type: "public-key",
      id,
      transports: ["internal", "hybrid", "usb", "nfc", "ble"],
    })) ?? [];

    const options = {
      rpId: this.rpId,
      challenge,
      timeout: 300_000,
      userVerification: "required",
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    };

    return { challenge, rpId: this.rpId, timeout: 300_000, options };
  }

  async completeAuthentication(opts: {
    challenge:          string;
    credentialId:       string;    // base64url
    authenticatorData:  string;    // base64url
    clientDataJSON:     string;    // base64url
    signature:          string;    // base64url DER-encoded signature
    userHandle?:        string;    // base64url user ID from authenticator
  }): Promise<{
    ok:      boolean;
    userId?: string;
    credentialId?: string;
    reason?: string;
  }> {
    try {
      // 1. Verify challenge
      const ch = this.challenges.get(opts.challenge);
      if (!ch || ch.type !== "auth") return { ok: false, reason: "invalid challenge" };
      if (Date.now() > ch.expiresAt)  return { ok: false, reason: "challenge expired" };
      this.challenges.delete(opts.challenge);

      // 2. Load stored credential
      const row = this.db.prepare(
        "SELECT * FROM credentials WHERE id = ?"
      ).get(opts.credentialId) as any;

      if (!row) return { ok: false, reason: "credential not found" };

      // 3. Verify clientDataJSON
      const clientData = JSON.parse(
        new TextDecoder().decode(b64urlDecode(opts.clientDataJSON))
      );
      if (clientData.type !== "webauthn.get")    return { ok: false, reason: "wrong type" };
      if (clientData.challenge !== opts.challenge) return { ok: false, reason: "challenge mismatch" };
      if (!clientData.origin.startsWith(this.origin)) return { ok: false, reason: "origin mismatch" };

      // 4. Parse authenticator data
      const authData = b64urlDecode(opts.authenticatorData);
      const rpIdHash = authData.slice(0, 32);
      const flags    = authData[32];
      const counter  = new DataView(authData.buffer, authData.byteOffset + 33).getUint32(0, false);

      // Verify RP ID hash
      const expectedRpIdHash = await sha256Raw(this.rpId);
      if (!timingSafeEqual(rpIdHash, expectedRpIdHash)) {
        return { ok: false, reason: "rpId hash mismatch" };
      }

      // Verify flags
      if (!(flags & 0x01)) return { ok: false, reason: "user presence not confirmed" };
      if (!(flags & 0x04)) return { ok: false, reason: "user verification not confirmed" };

      // 5. Verify counter (replay protection)
      if (counter !== 0 && counter <= row.counter) {
        // Counter went backwards  possible cloned authenticator
        return { ok: false, reason: `counter regression: stored=${row.counter} received=${counter}` };
      }

      // 6. Verify signature
      // The signed data = authData || SHA-256(clientDataJSON)
      const clientDataHash = await sha256Raw(b64urlDecode(opts.clientDataJSON));
      const signedData     = new Uint8Array(authData.length + clientDataHash.length);
      signedData.set(authData, 0);
      signedData.set(clientDataHash, authData.length);

      let jwk: JsonWebKey; try { jwk = JSON.parse(row.public_key_jwk); } catch { return { valid: false, reason: "corrupt key data" }; }
      const publicKey = await importPublicKey(jwk);
      const sigBytes  = b64urlDecode(opts.signature);

      let algorithm: AlgorithmIdentifier | EcdsaParams | RsaPssParams;
      if      (jwk.alg === "ES256")  algorithm = { name: "ECDSA", hash: "SHA-256" };
      else if (jwk.alg === "ES384")  algorithm = { name: "ECDSA", hash: "SHA-384" };
      else if (jwk.alg === "EdDSA")  algorithm = "Ed25519";
      else if (jwk.alg === "RS256")  algorithm = { name: "RSASSA-PKCS1-v1_5" };
      else throw new Error(`Unknown algorithm: ${jwk.alg}`);

      const valid = await crypto.subtle.verify(algorithm, publicKey, sigBytes, signedData);
      if (!valid) return { ok: false, reason: "signature invalid" };

      // 7. Update counter
      this.db.prepare(
        "UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?"
      ).run(counter, Date.now(), opts.credentialId);

      return { ok: true, userId: row.user_id, credentialId: opts.credentialId };
    } catch (err: any) {
      return { ok: false, reason: err.message };
    }
  }

  //  Credential management 

  getCredentialsForUser(userId: string): PasskeyCredential[] {
    return (this.db.prepare("SELECT * FROM credentials WHERE user_id = ?").all(userId) as any[])
      .map(r => ({
        id:           r.id,
        userId:       r.user_id,
        publicKeyJwk: r.public_key_jwk,
        counter:      r.counter,
        aaguid:       r.aaguid,
        transports:   (() => { try { return JSON.parse(r.transports ?? "[]"); } catch { return []; } })(),
        deviceName:   r.device_name,
        createdAt:    r.created_at,
        lastUsedAt:   r.last_used_at,
      }));
  }

  deleteCredential(credentialId: string, userId: string): boolean {
    const result = this.db.prepare(
      "DELETE FROM credentials WHERE id = ? AND user_id = ?"
    ).run(credentialId, userId);
    return (result as any).changes > 0;
  }

  renameCredential(credentialId: string, userId: string, name: string): void {
    this.db.prepare(
      "UPDATE credentials SET device_name = ? WHERE id = ? AND user_id = ?"
    ).run(name, credentialId, userId);
  }

  private guessDeviceName(aaguid: string, transports: string[]): string {
    // Common AAGUID  device name mapping
    const known: Record<string, string> = {
      "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Windows",
      "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
      "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello PIN",
      "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello facial recognition",
      "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain",
      "531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
      "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
      "f3809540-7f14-49c1-a8b3-8f813b225541": "Enpass",
    };

    if (known[aaguid]) return known[aaguid];
    if (transports.includes("internal")) return "Platform authenticator";
    if (transports.includes("usb"))      return "Security key (USB)";
    if (transports.includes("nfc"))      return "Security key (NFC)";
    return "Passkey";
  }

  close() { this.db.close(); }
}

//  Timing-safe comparison 

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
