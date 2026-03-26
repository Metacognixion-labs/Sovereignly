"use client";

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Report to error monitoring (wired in H6)
    console.error("[GlobalError]", error);
    if (typeof window !== "undefined" && (window as any).__SOVEREIGN_REPORT_ERROR) {
      (window as any).__SOVEREIGN_REPORT_ERROR(error);
    }
  }, [error]);

  return (
    <html lang="en">
      <body style={{ margin: 0, background: "#050a10", color: "#f0f2f5", fontFamily: "system-ui, sans-serif", display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" }}>
        <div style={{ textAlign: "center", maxWidth: 420, padding: 40 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>!</div>
          <h1 style={{ fontSize: 20, fontWeight: 600, marginBottom: 8 }}>Something went wrong</h1>
          <p style={{ fontSize: 13, color: "#94a3b8", marginBottom: 24, fontFamily: "monospace" }}>
            {error.digest ? `Error ID: ${error.digest}` : "An unexpected error occurred"}
          </p>
          <button
            onClick={reset}
            style={{
              padding: "10px 24px", background: "#4CAF50", color: "#050a10",
              border: "none", borderRadius: 8, fontSize: 14, fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Try Again
          </button>
        </div>
      </body>
    </html>
  );
}
