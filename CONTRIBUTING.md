# Contributing

Thank you for improving AI Context Hub. This repository is a local-first source preview; changes must preserve the read-only project boundary and fail closed on uncertain security state.

## Set up

```sh
git clone https://github.com/mason2048/ai-context-hub.git
cd ai-context-hub
npm ci
npm run dev
```

Use Node.js 20.19+ or 22.12+. Create a focused branch and keep pull requests small enough to review.

## Required checks

```sh
npm test
npm run build
npm audit
```

Add or update tests for behavior changes. Security-sensitive changes should include a regression that proves rejected input is not echoed or persisted.

## Repository rules

- Never commit credentials, `.env` files, signing keys, private project data, generated state, dependency trees, build output, or test reports.
- Preserve `sample-project/node_modules/ignored-rule/AGENTS.md`; it is an intentional inert ignore-rule fixture.
- Do not make scans write into source projects or execute scanned/imported text.
- Keep the API loopback-only, origin/host protected, and fail closed on incomplete scans, invalid imports, stale previews, and budget gates.
- Update both English and Chinese user documentation when commands or behavior change.

## Pull requests

Describe the problem, behavior change, tests run, and security/privacy impact. Do not attach sensitive screenshots or data. By submitting a contribution, you agree that it is licensed under Apache-2.0.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
