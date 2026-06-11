# ATT&CK Mapping — Stagecomp Downloader

**TLP:CLEAR** · Author: Yanky Wilson ([github.com/yankywilson](https://github.com/yankywilson)) · 2026-06-11

Each technique below is tied to a concrete, hand-verified observation in the loader. Techniques that were *claimed* by automated tooling but not supported by the binary are listed at the bottom as **not mapped**, with the reason.

| Tactic | Technique | ID | Evidence in the sample |
|---|---|---|---|
| Resource Development | Acquire/abuse code-signing | T1553.002 | Loader signed with an abused **Microsoft Trusted Signing** cert ("Donald Gay"), since revoked |
| Execution | Windows Command Shell | T1059.003 | `cmd.exe /c ping … && del …` for self-delete; `CreateProcessA` launches `Game.exe` |
| Defense Evasion | File Deletion (self) | T1070.004 | `FUN_004017f0` builds and runs the ping-delay self-delete on the success branch |
| Defense Evasion | Masquerading | T1036 | Drops `WebView2Loader.dll`; version-info reads `DISPLAY drives Handeler`; benign-looking `Game.exe` / `GameFiles` |
| Discovery | System Language Discovery | T1614.001 | Reads `…\NLS\Language` registry value (the only registry op) |
| Discovery | System Owner/User Discovery | T1033 | `GetUserNameA` for the beacon `client_id` |
| Discovery | System Information Discovery | T1082 | `GetComputerNameA`; `%USERDOMAIN%` resolution |
| Discovery | File and Directory Discovery | T1083 | Resolves Downloads / Public\Downloads to stage payloads |
| Command and Control | Application Layer Protocol: Web | T1071.001 | WinHTTP over HTTPS to `moonzonet.com`; JSON beacons to `/register`, `/check`, `/status` |
| Command and Control | Ingress Tool Transfer | T1105 | `GET /download/Game.{dll,exe,config}` → writes second stage to disk |

## Notes on confidence

- **T1057 (Process Discovery)** was flagged by CAPA but is **weak** — likely a string-table false positive (no process-enumeration logic was confirmed by hand). Included in the summary list for completeness but treated as low-confidence.
- The sample has **no persistence** technique (launch-and-exit), **no privilege escalation** (manifest `asInvoker`, no UAC), **no mutex**, and **no string obfuscation** (FLOSS returned effectively null). Their *absence* is a finding: this is a minimal courier, not a full RAT.

## Not mapped (claimed but unsupported)

| Claimed | Source | Why excluded |
|---|---|---|
| Anti-analysis / sandbox evasion via TLS timing ("217-cycle loop") | sandbox heuristic | Implementation/Schannel artifact; no evasion logic in the binary |
| Telegram C2 | one sandbox run | Browser following the decoy page; the loader contains no Telegram code |
| Additional URI handlers `/checker`, `/checknt` | sandbox parser | Parsing artifacts; contradicted by the decompiled request paths |
