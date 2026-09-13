/** @type {import('next').NextConfig} */
const API = process.env.AEGIS_API_URL || "http://127.0.0.1:8000";
const nextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API}/api/:path*` }];
  },
};
export default nextConfig;
