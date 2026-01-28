import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const issuerBase =
    env.VITE_WALTID_ISSUER_BASE ||
    env.VITE_ISSUER_API_BASE ||
    "http://192.168.93.134:7002";

  return {
    server: {
      host: "::",
      port: 8080,
      proxy: {
        "/openid4vc": {
          target: issuerBase,
          changeOrigin: true,
        },
      },
    },
    plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  };
});
