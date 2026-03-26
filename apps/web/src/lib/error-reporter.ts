"use client";

/**
 * Client-side error reporter — sends errors to /_sovereign/errors/report
 * for logging to SovereignChain audit trail.
 *
 * Auto-initializes on import:
 *   - window.onerror for uncaught errors
 *   - window.onunhandledrejection for unhandled promises
 *   - window.__SOVEREIGN_REPORT_ERROR for manual reporting (used by error boundaries)
 */

let initialized = false;

function reportError(error: { message: string; stack?: string; url?: string; digest?: string; componentStack?: string }): void {
  // Fire-and-forget — don't let error reporting cause more errors
  fetch("/_sovereign/errors/report", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "sovereignly" },
    credentials: "include",
    body: JSON.stringify({
      message: error.message,
      stack: error.stack?.slice(0, 2000), // Truncate stack to prevent huge payloads
      url: error.url ?? (typeof window !== "undefined" ? window.location.href : undefined),
      digest: error.digest,
      componentStack: error.componentStack?.slice(0, 1000),
    }),
  }).catch(() => {}); // Silently ignore reporting failures
}

export function initErrorReporter(): void {
  if (initialized || typeof window === "undefined") return;
  initialized = true;

  // Global error handler for uncaught errors
  window.onerror = (message, source, lineno, colno, error) => {
    reportError({
      message: typeof message === "string" ? message : "Unknown error",
      stack: error?.stack,
      url: source ?? window.location.href,
    });
  };

  // Unhandled promise rejections
  window.onunhandledrejection = (event) => {
    const reason = event.reason;
    reportError({
      message: reason?.message ?? String(reason),
      stack: reason?.stack,
    });
  };

  // Hook for error boundaries to call
  (window as any).__SOVEREIGN_REPORT_ERROR = (error: Error & { digest?: string }) => {
    reportError({
      message: error.message,
      stack: error.stack,
      digest: error.digest,
    });
  };
}

export { reportError };
