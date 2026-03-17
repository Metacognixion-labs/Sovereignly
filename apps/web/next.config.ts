import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/_sovereign/:path*",
        destination: `${process.env.SOVEREIGN_API_URL ?? "http://localhost:8787"}/_sovereign/:path*`,
      },
      {
        source: "/.well-known/:path*",
        destination: `${process.env.SOVEREIGN_API_URL ?? "http://localhost:8787"}/.well-known/:path*`,
      },
    ];
  },
};

export default nextConfig;
