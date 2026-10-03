import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // These tests hit a real Postgres database (see src/__tests__/setup.ts).
    // Running them in parallel across files would mean multiple test files
    // truncating the same tables at the same time - so we force everything
    // onto a single worker. This is slower than fully parallel unit tests,
    // but it's an honest trade: these ARE integration tests, not pure unit
    // tests, because the whole point is proving the SQL is correct, not
    // just the TypeScript.
    fileParallelism: false,
    environment: "node",
    setupFiles: ["./src/__tests__/setup.ts"],
    testTimeout: 15000,
  },
});
