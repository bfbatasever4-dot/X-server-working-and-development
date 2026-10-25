# X Server Implementation Update

**Date:** 2026-10-24
**Product:** RTAD / X Server
**Target:** OPPO A15, Android 10, Termux, approximately 2 GB RAM
**Current status:** Host-side implementation and regression work completed for this execution; physical-device validation remains pending.

## Baseline and preservation

- Started on branch `main`, baseline commit `a5701ff` (`X server`). The tracked application and README had no modifications at task start. `Update.md`, `Maker.md`, `Error.md`, and `references/` were already untracked user content and were preserved/updated rather than discarded.
- The default workspace runtime paths (`data/`, `data/xserver.sqlite3`, `data/session_secret`, and `logs/`) did not exist at inspection. No production database or existing account was available in this checkout to back up or modify.
- Existing `x_server.py` behavior was inspected before edits and retained. The prior Git commit is the source rollback point; no new commit or stash was created.
- No reference source files were changed, moved, or copied into the runtime.

## Implemented

| Area | Actual change |
|---|---|
| Existing Flask/SQLite core | Preserved setup/login, catalog, details, playback, My List, progress, settings, and Minecraft pages. Added `XSERVER_DATA_DIR`/`XSERVER_LOG_DIR` path configuration while retaining existing default paths. |
| Authentication/security | Added CSRF-protected POST logout and password change with current-password verification and all-session revocation; bounded password lengths; safe same-origin login redirect validation; retained password hashing, login throttling, session lifetime, and first-run-only setup. Added response security headers and restrictive permissions for a newly created DB/session key. |
| Settings/schema | Added an additive `settings` table to persist the movie-directory choice when `XSERVER_MOVIE_DIR` is not explicitly set. Existing account/list/progress/metadata/login rows are preserved. |
| X Stream | Preserved local scanning, supported extensions, opaque path keys, chunked media delivery, Range responses, resume progress, and list behavior. Deduplicates resolved files, skips symlinks, and supports manually managed local posters. |
| X Terminal | Added authenticated persistent PTY sessions bound to the actual Flask host environment. The page and APIs require loopback server bind and loopback client; working directory persists; logout and app shutdown terminate sessions. |
| X Bot | Added separate `x_bot.py` and `x_bot_config.json`; supports project inspection, fixed approved tests/compile/Git tools, read-only service diagnostics, diff preview, explicit apply approval, private backups, and guarded rollback. No model/API key integration or arbitrary command input. |
| X File Server | Added authenticated browsing, navigation, upload, download, and file deletion within a configured root. Resolved-path checks prevent traversal; overwrite/deletion require confirmation; recursive folder deletion is disabled. |
| Central logs | Added a dedicated Logs page with severity/source filters and refresh/clear. X Server and Minecraft logs rotate; real Minecraft output is collected; secrets are redacted from bot/log display. |
| Diagnostics | Retained the authenticated read-only health/status page independently of service controls. |
| Minecraft | Preserved explicit JAR selection, EULA check, process identity checks, verified stop/restart, and resource limits. Startup failures and unverifiable managed exits are logged. No real PaperMC/Geyser/Floodgate server was launched. |
| Backup/restore | Retained `scripts/data_tools.py` for SQLite online backup, integrity verification, and restore only into a new destination. |
| Verification | Added isolated module tests. Current result: 20 tests passed, including actual host PTY commands, file transfers/path rejection, approved Git execution, backup/apply/rollback, posters, log filtering, and Minecraft log rotation. |

## Tests and checks run

| Command/check | Result |
|---|---|
| `python -m unittest discover -s tests -v` | **PASS** — 20 tests, 0 failures, run 2026-10-24. |
| `python -m py_compile x_server.py x_terminal.py x_bot.py` | **PASS**. |
| Real PTY commands | **PASS** — `pwd`, persistent `cd`, Python, and `git --version` executed in the actual host environment. |
| Real local server start/HTTP response/clean shutdown | **PASS** — Python 3.14.2, Linux x86_64 Codespaces; HTTP 200 first-run page and security headers; stopped with SIGINT (exit 0). |
| Process RSS after local startup and request | **41,916 kB** — Linux 6.8 Azure x86_64/glibc 2.39, Python 3.14.2, Flask 3.1.3. This is a single idle server process after one login-page request; no browser, video, Android, or Minecraft workload. |
| Backup/verify/restore CLI | **PASS** — create and integrity-check backup, restore to a new path, and verify preserved row/key using disposable database. |
| `git diff --check` | **PASS**. Final review confirmed the reference trees and runtime data paths were not modified/created. |
| OPPO A15 / Android 10 / Termux tests | **Not run** — target device unavailable. |

The automated tests use disposable temporary data and do not access a production database, run Minecraft, use TMDB, or access any reference repository.

## Current limitations and blockers

- **Device support:** OPPO A15/Android 10/Termux permissions, Python compatibility, codec playback, background stability, and RAM/battery use are not verified.
- **Minecraft:** Manager behavior is tested without starting a game server. A 512 MiB heap excludes JVM/native memory and is not a safe-use claim for a 2 GB phone.
- **Terminal:** Loopback-only and tested in Codespaces; Termux shell behavior, Android lifecycle, and mobile browser interaction remain unverified on the target phone.
- **X Bot:** Bounded local tool agent, not a generative AI assistant. Commands are fixed/allowlisted; only existing project files can be changed.
- **Remote access:** No LAN, VPN, reverse proxy, Tor, or Onion Service configuration is implemented. Localhost remains the default.
- **Licensing:** Cine App source has no identified root `LICENSE`, `NOTICE`, or `COPYING` file; reuse/redistribution rights remain unresolved and no code was copied. The inspected Pterodactyl root license is MIT; it is not used by the app. Future assets still require file-level notice review.
- **Metadata:** TMDB is optional, external, and not tested; local library features do not depend on it.
- **Backup:** Temporary backup/verification/restore-to-new-location is covered by tests. No production backup exists because no workspace database was present. Production cutover/restore into a live data path is intentionally not automated.

## Modified/added files

- `x_server.py`
- `x_terminal.py`
- `x_bot.py`
- `x_bot_config.json`
- `README.md`
- `Update.md`
- `Maker.md`
- `Error.md`
- `.gitignore`
- `requirements.txt`
- `scripts/data_tools.py`
- `tests/test_x_server.py`

Removed only the unused `references/xterm.js/` clone. Other reference repositories were preserved.

## Next steps

1. Run the OPPO A15 acceptance matrix in `Maker.md`; record actual Android/Termux versions, storage behavior, browser codec tests, RSS, and background reliability.
2. Keep the application bound to loopback. Design and test a private TLS/VPN boundary before any remote exposure.
3. Leave Minecraft stopped on the phone unless a separate device-specific memory/reliability assessment approves it.
4. Resolve Cine App reuse rights before considering source adoption.
