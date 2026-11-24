/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // SOC-style dark palette. Kept as named tokens so components never
        // hard-code raw hex values.
        surface: {
          DEFAULT: "#0b0f14",
          raised: "#111722",
          card: "#151c28",
          border: "#232c3a",
        },
        accent: {
          DEFAULT: "#22d3ee",
          muted: "#0e7490",
        },
        status: {
          ok: "#34d399",
          warn: "#fbbf24",
          danger: "#f87171",
          idle: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
