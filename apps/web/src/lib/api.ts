"use client";

import { useStore } from "@/stores/config";

export async function api<T = unknown>(
  path: string,
  opts: RequestInit = {}
): Promise<{ ok: boolean; status: number; data: T | null }> {
  const { endpoint } = useStore.getState();
  const base = endpoint || "";

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Requested-With": "sovereignly", // CSRF protection for cookie-based auth
      ...(opts.headers as Record<string, string>),
    };

    const res = await fetch(`${base}${path}`, {
      ...opts,
      headers,
      credentials: "include", // Send httpOnly cookies automatically
      signal: opts.signal ?? AbortSignal.timeout(10_000),
    });
    const data = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, data: data as T };
  } catch {
    return { ok: false, status: 0, data: null };
  }
}
