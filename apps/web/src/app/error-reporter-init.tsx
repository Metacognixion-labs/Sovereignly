"use client";

import { useEffect } from "react";
import { initErrorReporter } from "@/lib/error-reporter";

export function ErrorReporterInit() {
  useEffect(() => { initErrorReporter(); }, []);
  return null;
}
