import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // The exact o200k_base rank table is lazily initialized once per worker.
    // Keep a realistic cold-start ceiling so parallel system load cannot turn
    // a passing scanner assertion into a spurious five-second timeout.
    testTimeout: 15_000,
    hookTimeout: 15_000,
    coverage: { reporter: ['text', 'json-summary'] },
  },
});
