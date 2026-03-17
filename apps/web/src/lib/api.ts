"use client";

import { useStore } from "@/stores/config";

export async function api<T = unknown>(
  path: string,
  opts: RequestInit = {}
): Promise<{ ok: boolean; status: number; data: T | null }> {
  const { endpoint, adminToken, jwtToken } = useStore.getState();
  const base = endpoint || "";

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(opts.headers as Record<string, string>),
    };
    if (adminToken) headers["x-sovereign-token"] = adminToken;
    if (jwtToken) headers["Authorization"] = `Bearer ${jwtToken}`;

    const res = await fetch(`${base}${path}`, {
      ...opts,
      headers,
      signal: opts.signal ?? AbortSignal.timeout(10_000),
    });
    const data = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, data: data as T };
  } catch {
    return { ok: false, status: 0, data: null };
  }
}
