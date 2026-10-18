import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  base: "./",
  server: { host: "0.0.0.0", allowedHosts: ["terminal.local"] },
  build: {
    rollupOptions: {
      input: Object.fromEntries(
        [
          "index",
          "guide",
          "guard",
          "coverage",
          "tools",
          "engineering",
          "review",
          "support",
        ].map(
          (name) => [
            name,
            fileURLToPath(new URL(`./${name}.html`, import.meta.url)),
          ],
        ),
      ),
    },
  },
});
