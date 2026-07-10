import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // Treat unzipper as an external package at runtime — its main entry has a
  // lazy require('@aws-sdk/client-s3') inside an S3 helper that we never call,
  // but Turbopack tries to statically resolve it at bundle time and fails.
  // Externalizing the package lets Node's runtime require it lazily instead.
  serverExternalPackages: ["unzipper"],
};

export default nextConfig;
