import { Globe } from "lucide-react";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <img src="/logo.svg" alt="Sovereignly" className="w-14 h-14 mx-auto mb-4 drop-shadow-[0_0_12px_rgba(76,175,80,0.3)]" />
          <h1 className="text-xl font-semibold tracking-tight">Sovereignly</h1>
          <p className="text-sm text-text-muted mt-1">Sovereign cloud infrastructure</p>
        </div>
        {children}
      </div>
    </div>
  );
}
