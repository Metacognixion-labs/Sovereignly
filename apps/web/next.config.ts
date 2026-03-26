import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",

  // Performance: compress output, optimize images
  compress: true,
  images: {
    formats: ["image/avif", "image/webp"],
  },

  // Security: restrict powered-by header
  poweredByHeader: false,

  // Performance: optimize package imports for tree-shaking
  experimental: {
    optimizePackageImports: ["lucide-react"],
  },

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

  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
      {
        // Cache static assets aggressively
        source: "/_next/static/(.*)",
        headers: [
          { key: "Cache-Control", value: "public, max-age=31536000, immutable" },
        ],
      },
    ];
  },
};

export default nextConfig;
