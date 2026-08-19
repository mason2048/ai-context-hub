# AI Context Hub

[中文](README.zh-CN.md) · [User guide](docs/USER_GUIDE.md) · [Security](SECURITY.md)

AI Context Hub is a local-first workspace for reviewing the instructions, Skills, knowledge files, and MCP metadata that may be supplied to an AI coding agent. It scans a project without modifying it, builds immutable snapshots, highlights risks, counts the exact exported tokens, and creates a reviewed Context Package v0.1 or an `AGENTS.md` draft.

Version `0.1.0` is a **source preview**. It is not a hosted service and a successful export does not prove that a downstream agent consumed the package correctly.

## Quick start

Requirements: Node.js 20.19+ or 22.12+ and npm.

```sh
git clone https://github.com/mason2048/ai-context-hub.git
cd ai-context-hub
npm ci
npm run dev
```

Open <http://127.0.0.1:43100>, keep the prefilled `sample-project` path, and select **Start read-only scan**. The development command starts both the API on `127.0.0.1:43101` and the Vite UI on `127.0.0.1:43100`. Stop both with `Ctrl+C` in the terminal.

For a production build served locally:

```sh
npm run build
npm start
```

Then open <http://127.0.0.1:43101>.

## What it does

- Finds `AGENTS.md`, `CLAUDE.md`, Copilot/Cursor rules, `SKILL.md`, Markdown knowledge, and safe MCP server-name metadata.
- Records relative sources, locators, SHA-256 revisions, modification times, summaries, scopes, and exact `o200k_base` token counts.
- Detects duplicates, structured conflicts, broken relative links, and suspected secrets while discarding matched secret values.
- Preserves multiple projects as immutable local snapshots and shows refresh differences.
- Imports Context Package v0.1 JSON through inspect-and-confirm, without fetching or executing declared sources.
- Exports reviewed JSON or an `AGENTS.md` draft with warn, block, or deterministic auto-trim token budgets.
- Optionally signs JSON with a local Ed25519 key.

## Privacy and safety

The service binds only to the loopback interface, has no account, telemetry, automatic upload, or cloud-model requirement, and never executes scanned scripts, Skills, prompts, or MCP commands. Scans do not write into the target project. Exported JSON may contain absolute file URIs, so review it before sharing.

The default state directory is:

- macOS: `~/Library/Application Support/AI Context Hub/v1`
- other systems: `~/.local/share/ai-context-hub/v1`

Override it with an absolute, non-overlapping directory:

```sh
CONTEXT_HUB_DATA_DIR=/absolute/private/context-hub-state npm start
```

See the [user guide](docs/USER_GUIDE.md) for scanning, filtering, budgeting, import/export, backup, reset, and troubleshooting procedures.

## Verification

```sh
npm test
npm run build
npm audit
```

The `sample-project/node_modules/ignored-rule/AGENTS.md` file is an intentional inert fixture used to prove that dependency directories are excluded. Do not remove it as cleanup.

## Project status and limits

This preview has automated local coverage for scanning, snapshots, import, export, signing, cancellation, and API security. Real-user adoption and downstream-agent consumption remain external validation work. The project does not include cloud sync, teams, accounts, automatic config writes, automatic command execution, or production deployment.

## Contributing and license

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report security issues through GitHub Private Vulnerability Reporting as described in [SECURITY.md](SECURITY.md).

Licensed under the [Apache License 2.0](LICENSE).
