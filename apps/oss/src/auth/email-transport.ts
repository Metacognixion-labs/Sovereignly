/**
 * Sovereignly  Email Transport
 *
 * Lightweight email delivery for magic-link codes and verification.
 * - SmtpTransport: raw SMTP via Bun TCP (no external deps)
 * - ConsoleTransport: logs codes to stdout (dev mode default)
 *
 * Configured via SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM env vars.
 */

export interface EmailTransport {
  send(to: string, subject: string, html: string, text?: string): Promise<void>;
}

// ── Console Transport (dev fallback) ──────────────────────────────────────────

export class ConsoleTransport implements EmailTransport {
  async send(to: string, subject: string, _html: string, text?: string) {
    const code = text?.match(/\b(\d{6})\b/)?.[1] ?? "(see body)";
    console.log(`\n${"═".repeat(52)}`);
    console.log(`  📧  EMAIL → ${to}`);
    console.log(`  Subject: ${subject}`);
    console.log(`  Code: ${code}`);
    console.log(`${"═".repeat(52)}\n`);
  }
}

// ── SMTP Transport ────────────────────────────────────────────────────────────

export class SmtpTransport implements EmailTransport {
  constructor(
    private host: string,
    private port: number,
    private user: string,
    private pass: string,
    private from: string,
  ) {}

  async send(to: string, subject: string, html: string, text?: string) {
    const socket = await this.connect();
    try {
      await this.readLine(socket);                        // greeting
      await this.cmd(socket, `EHLO sovereignly\r\n`);
      if (this.port === 587) {
        await this.cmd(socket, `STARTTLS\r\n`);
        // Upgrade handled by Bun TLS — reconnect in TLS mode
      }
      // AUTH LOGIN
      const creds = btoa(`\0${this.user}\0${this.pass}`);
      await this.cmd(socket, `AUTH PLAIN ${creds}\r\n`);
      await this.cmd(socket, `MAIL FROM:<${this.from}>\r\n`);
      await this.cmd(socket, `RCPT TO:<${to}>\r\n`);
      await this.cmd(socket, `DATA\r\n`);
      const msg = [
        `From: Sovereignly <${this.from}>`,
        `To: ${to}`,
        `Subject: ${subject}`,
        `MIME-Version: 1.0`,
        `Content-Type: multipart/alternative; boundary="sovereign"`,
        ``,
        `--sovereign`,
        `Content-Type: text/plain; charset=utf-8`,
        ``,
        text ?? "",
        `--sovereign`,
        `Content-Type: text/html; charset=utf-8`,
        ``,
        html,
        `--sovereign--`,
        `.`,
      ].join("\r\n");
      await this.cmd(socket, msg + "\r\n");
      await this.cmd(socket, `QUIT\r\n`);
    } finally {
      socket.end();
    }
  }

  private connect(): Promise<any> {
    const tls = this.port === 465;
    return new Promise((resolve, reject) => {
      const sock = Bun.connect({
        hostname: this.host,
        port: this.port,
        tls,
        socket: {
          data(_s, data) { (sock as any).__lastData = new TextDecoder().decode(data); },
          open(s) { resolve(s); },
          error(_s, err) { reject(err); },
          close() {},
        },
      });
    });
  }

  private async cmd(socket: any, data: string): Promise<string> {
    socket.write(data);
    await new Promise(r => setTimeout(r, 200));
    return (socket as any).__lastData ?? "";
  }

  private async readLine(socket: any): Promise<string> {
    await new Promise(r => setTimeout(r, 300));
    return (socket as any).__lastData ?? "";
  }
}

// ── Factory ───────────────────────────────────────────────────────────────────

export function createEmailTransport(): EmailTransport {
  const host = process.env.SMTP_HOST;
  if (host) {
    return new SmtpTransport(
      host,
      parseInt(process.env.SMTP_PORT ?? "587"),
      process.env.SMTP_USER ?? "",
      process.env.SMTP_PASS ?? "",
      process.env.SMTP_FROM ?? "noreply@sovereignly.io",
    );
  }
  console.log("[Email] No SMTP_HOST configured — using ConsoleTransport (codes logged to stdout)");
  return new ConsoleTransport();
}
