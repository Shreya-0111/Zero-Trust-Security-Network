import nextCoreWebVitals from "eslint-config-next/core-web-vitals"

const nextConfig = Array.isArray(nextCoreWebVitals) ? nextCoreWebVitals : nextCoreWebVitals.default

const config = [
  {
    ignores: ["node_modules/**", ".next/**"],
  },
  ...(nextConfig || []),
  {
    rules: {
      "@next/next/no-img-element": "off",
    },
  },
]

export default config
