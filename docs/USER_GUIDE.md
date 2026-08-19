# AI Context Hub user guide

[中文操作手册](USER_GUIDE.zh-CN.md)

## 1. Install and start

Install Node.js 20.19+ or 22.12+, then run:

```sh
git clone https://github.com/mason2048/ai-context-hub.git
cd ai-context-hub
npm ci
npm run dev
```

Open <http://127.0.0.1:43100>. Keep the terminal open. Stop the UI and API together with `Ctrl+C`.

To test the built application instead:

```sh
npm run build
npm start
```

Open <http://127.0.0.1:43101> and stop with `Ctrl+C`.

## 2. First scan

1. Start with the prefilled absolute path to `sample-project`.
2. Review the displayed include rules, hard exclusions, and scan limits.
3. Select **Start read-only scan** and wait for completion.
4. Confirm that rules, Skills, knowledge, tool metadata, and risk entries appear.
5. Open the risk panel to see the intentional command conflict, duplicate, broken link, and redacted-secret examples.

For a real project, enter its absolute root path. The state directory must not be inside, above, or otherwise overlap the scanned project. Symlinks, secret files, dependency trees, build output, and configured hard exclusions are not followed.

## 3. Filter and review

Use text search plus type, scope, risk, and source filters. Open an item to review its summary, relative source, locator, revision, scope, sensitivity, tags, and token count. Clear an item's checkbox to exclude it from the current export; this does not edit the source project or delete the snapshot.

## 4. Refresh and compare

Open a saved project and choose refresh. A successful refresh creates a new immutable snapshot and reports added, changed, removed, and unchanged items. A cancelled, failed, truncated, or limit-exceeded refresh does not replace the last complete snapshot.

## 5. Token budget and export

1. Open **Export preview**.
2. Choose Context Package JSON or `AGENTS.md`.
3. Enter the maximum token budget.
4. Select `warn`, `block`, or `auto-trim`.
5. Optionally enable Ed25519 signing for JSON.
6. Generate a fresh preview and inspect the full body, exact token count, included items, and omissions.
7. Download only after that review.

`block` rejects an over-budget export. `auto-trim` removes lower-priority items deterministically and lists omissions. Any selection or option change invalidates the previous preview. JSON can include absolute source URIs; remove sensitive metadata before sharing it outside the trusted machine.

## 6. Import a package

1. Select **Import Context Package**.
2. Choose a JSON file in the browser.
3. Review schema, producer, item counts, sensitivity, signature status, and warnings.
4. Confirm to create a local imported snapshot.

The importer reads the selected JSON text only. It does not fetch source URLs, read paths declared inside the package, execute content, or copy the original JSON file into a project. Invalid schemas, duplicate item IDs, plaintext secrets, invalid signatures, and size-limit violations fail closed.

## 7. Backup and restore

Stop the application before copying state. The default state directory is:

- macOS: `~/Library/Application Support/AI Context Hub/v1`
- other systems: `~/.local/share/ai-context-hub/v1`

Back up that entire directory, including manifest, snapshots, and signing material, using an access-controlled local backup. Restore only while the application is stopped and preserve file permissions. Do not publish this directory.

For isolated evaluation, start with a dedicated absolute location:

```sh
CONTEXT_HUB_DATA_DIR=/absolute/private/context-hub-evaluation npm start
```

## 8. Reset or remove local data

There is no silent reset command. Stop the application, verify the exact state path, back it up if needed, and move that one directory to the operating-system Trash. Never remove a broad parent directory. Restarting creates fresh state on first successful save. This is irreversible after Trash is emptied and does not alter scanned projects.

To remove the application source, stop it and remove only the cloned `ai-context-hub` directory. npm dependencies and `dist` are inside that clone; product state is separate.

## 9. Run checks

```sh
npm test
npm run build
npm audit
```

Tests include a deliberate `sample-project/node_modules/ignored-rule/AGENTS.md` fixture. It must remain present in a clean clone but absent from scan results.

## 10. Troubleshooting

- **Unsupported Node version:** use Node 20.19+ or 22.12+; avoid Node 21.
- **Port already in use:** stop the process using 43100 or 43101, then restart. These ports are intentionally fixed for the source preview.
- **Path rejected:** enter a real absolute directory and place `CONTEXT_HUB_DATA_DIR` outside the scanned tree.
- **Scan is partial:** reduce repository scope or remove excessive generated files, then refresh; partial results do not advance the latest complete snapshot.
- **Export blocked:** raise the budget, change to `warn`, use `auto-trim`, or deselect items after review.
- **Import rejected:** validate the JSON against `context-package.schema.json`; remove plaintext credentials and do not bypass signature or size checks.
- **Unexpected secret warning:** treat it as a possible real credential, rotate it if necessary, and remember that pattern matching may also produce false positives.
- **UI cannot call the API:** use the displayed loopback URL and do not proxy it through an untrusted origin.

## Support boundary

This source preview has no hosted backend, account recovery, production SLA, or guarantee that another AI tool will consume an export. Open a normal GitHub issue for reproducible non-sensitive bugs. Use Private Vulnerability Reporting for security findings.
