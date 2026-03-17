import { Globe } from "lucide-react";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-brand/10 border border-brand/20 mb-4">
            <Globe className="w-6 h-6 text-brand" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">Sovereignly</h1>
          <p className="text-sm text-text-muted mt-1">Sovereign cloud infrastructure</p>
        </div>
        {children}
      </div>
    </div>
  );
}
