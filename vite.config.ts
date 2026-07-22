import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "padmin-app",
  base: "/padmin/",
  plugins: [react()],
  build: {
    outDir: "../dist/padmin",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/padmin/api": "http://127.0.0.1:8090",
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "padmin-app/src"),
    },
  },
});
