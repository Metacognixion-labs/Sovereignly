"use client";

import { useEffect } from "react";
import { AlertTriangle, RotateCcw, Home } from "lucide-react";
import Link from "next/link";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[DashboardError]", error);
    if (typeof window !== "undefined" && (window as any).__SOVEREIGN_REPORT_ERROR) {
      (window as any).__SOVEREIGN_REPORT_ERROR(error);
    }
  }, [error]);

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="text-center max-w-md">
        <div className="w-12 h-12 rounded-xl bg-red/10 border border-red/20 flex items-center justify-center mx-auto mb-4">
          <AlertTriangle className="w-6 h-6 text-red" />
        </div>
        <h2 className="text-lg font-semibold mb-1">Page Error</h2>
        <p className="text-sm text-text-muted mb-2">This page encountered an error and couldn&apos;t render.</p>
        {error.digest && (
          <p className="text-[10px] font-mono text-text-muted mb-4">Error ID: {error.digest}</p>
        )}
        <p className="text-xs font-mono text-red/80 bg-red/5 border border-red/10 rounded-lg px-3 py-2 mb-6 break-all">
          {error.message || "Unknown error"}
        </p>
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={reset}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors"
          >
            <RotateCcw className="w-4 h-4" /> Retry
          </button>
          <Link
            href="/overview"
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm text-text-muted hover:text-text-primary transition-colors"
          >
            <Home className="w-4 h-4" /> Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
