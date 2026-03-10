/**
 * Sovereignly  Email Transport
 *
 * Priority: Resend HTTP API > SMTP > Console fallback
 *
 * Resend: single RESEND_API_KEY env var, free tier = 100 emails/day
 * SMTP: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 * Console: logs codes/links to stdout (dev mode)
 */

export interface EmailTransport {
  send(to: string, subject: string, html: string, text?: string): Promise<void>;
}

// ── Resend Transport (recommended) ────────────────────────────────────────────

export class ResendTransport implements EmailTransport {
  constructor(
    private apiKey: string,
    private from: string = "Sovereignly <noreply@sovereignly.io>",
  ) {}

  async send(to: string, subject: string, html: string, text?: string) {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: this.from,
        to: [to],
        subject,
        html,
        text,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: res.statusText }));
      console.error(`[Resend] Failed to send email to ${to}:`, err);
      throw new Error(`Email delivery failed: ${(err as any).message ?? res.statusText}`);
    }
  }
}

// ── Console Transport (dev fallback) ──────────────────────────────────────────

export class ConsoleTransport implements EmailTransport {
  async send(to: string, subject: string, _html: string, text?: string) {
    const code = text?.match(/\b(\d{6})\b/)?.[1];
    const link = text?.match(/(https?:\/\/\S+verify\S+)/)?.[1];
    console.log(`\n${"═".repeat(60)}`);
    console.log(`  EMAIL → ${to}`);
    console.log(`  Subject: ${subject}`);
    if (link) console.log(`  Magic Link: ${link}`);
    if (code) console.log(`  Code: ${code}`);
    console.log(`${"═".repeat(60)}\n`);
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
      await this.readLine(socket);
      await this.cmd(socket, `EHLO sovereignly\r\n`);
      if (this.port === 587) await this.cmd(socket, `STARTTLS\r\n`);
      const creds = btoa(`\0${this.user}\0${this.pass}`);
      await this.cmd(socket, `AUTH PLAIN ${creds}\r\n`);
      await this.cmd(socket, `MAIL FROM:<${this.from}>\r\n`);
      await this.cmd(socket, `RCPT TO:<${to}>\r\n`);
      await this.cmd(socket, `DATA\r\n`);
      const msg = [
        `From: Sovereignly <${this.from}>`, `To: ${to}`, `Subject: ${subject}`,
        `MIME-Version: 1.0`, `Content-Type: multipart/alternative; boundary="sovereign"`,
        ``, `--sovereign`, `Content-Type: text/plain; charset=utf-8`, ``, text ?? "",
        `--sovereign`, `Content-Type: text/html; charset=utf-8`, ``, html,
        `--sovereign--`, `.`,
      ].join("\r\n");
      await this.cmd(socket, msg + "\r\n");
      await this.cmd(socket, `QUIT\r\n`);
    } finally { socket.end(); }
  }

  private connect(): Promise<any> {
    return new Promise((resolve, reject) => {
      const sock = Bun.connect({
        hostname: this.host, port: this.port, tls: this.port === 465,
        socket: {
          data(_s, data) { (sock as any).__lastData = new TextDecoder().decode(data); },
          open(s) { resolve(s); }, error(_s, err) { reject(err); }, close() {},
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
  // Priority 1: Resend (recommended)
  const resendKey = process.env.RESEND_API_KEY;
  if (resendKey) {
    const from = process.env.EMAIL_FROM ?? "Sovereignly <noreply@sovereignly.io>";
    console.log("[Email] Using Resend transport");
    return new ResendTransport(resendKey, from);
  }

  // Priority 2: SMTP
  const smtpHost = process.env.SMTP_HOST;
  if (smtpHost) {
    console.log(`[Email] Using SMTP transport → ${smtpHost}`);
    return new SmtpTransport(
      smtpHost,
      parseInt(process.env.SMTP_PORT ?? "587"),
      process.env.SMTP_USER ?? "",
      process.env.SMTP_PASS ?? "",
      process.env.SMTP_FROM ?? "noreply@sovereignly.io",
    );
  }

  // Priority 3: Console (dev)
  console.log("[Email] No RESEND_API_KEY or SMTP_HOST — using ConsoleTransport (codes logged to stdout)");
  return new ConsoleTransport();
}
