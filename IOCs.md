# Indicators of Compromise — Stagecomp / moonzonet.com

**TLP:CLEAR** · Author: Yanky Wilson ([github.com/yankywilson](https://github.com/yankywilson)) · 2026-06-11

All indicators below were validated by hand (static RE) and/or confirmed across multiple OSINT sources. Confidence is per-indicator.

---

## Durable indicators (use these)

### File hashes — loader

| Type | Value |
|---|---|
| SHA-256 | `a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0` |
| SHA-1 | `0ba2306ec15f7124fafc7615e81f34c7986ba9a5` |
| MD5 | `7f3c8a7fe78d3d05b6022df3ea0c15fb` |
| imphash | `9963ebabcee092908eac2414f7c4661a` |

### Network

| Indicator | Value | Confidence / note |
|---|---|---|
| C2 domain | `moonzonet.com` | **High** — strongest network indicator |
| User-Agent (substring) | `StageClient/2.0` | High — anchor on substring; full header is `User-Agent: StageClient/2.0` |
| URI — register | `POST /register` | High |
| URI — poll | `POST /check` | High |
| URI — status | `POST /status` | High |
| URI — payload | `GET /download/Game.dll`, `/download/Game.exe`, `/download/Game.config` | High |
| TLS | port 443, `Content-Type: application/json` | Medium — generic alone |

### Host / endpoint

| Indicator | Value | Note |
|---|---|---|
| Drop — DLL | `WebView2Loader.dll` | sideload name (also a legit MS name — use with path) |
| Drop — stage 2 | `Game.exe` | generic name — use with path/context |
| Drop — config | `visualwincomp.txt` | **near-unique** string |
| Staging dir | `…\Downloads\GameFiles\`, `C:\Users\Public\Downloads` | |
| client_id format | `<ComputerName>_<UserName>_<TickCount>` | beacon identity |
| Gate tokens | `"approved":true` **and** `"retry":true` | **both are GO-signals** (see note) |
| Self-delete | `cmd.exe /c ping 127.0.0.1 -n 6 > nul && del /f /q "<self>"` | weak/generic |
| Version-info string | `DISPLAY drives Handeler` (misspelled) | masquerade artifact |
| InternalName / OrigName | `DIDS` / `DIDS.exe` | |
| Recon fallback literals | `Unknown`, `WORKGROUP` | low value alone |

### Code-signing (clustering anchor — Medium)

| Indicator | Value |
|---|---|
| Signer (revoked) | `Donald Gay` — abused Microsoft Trusted Signing cert; revoked. Treat as a clustering pivot, not operator identity. |

> **Behavioral note on the gate:** the loader proceeds to download on **either** `"approved":true` **or** `"retry":true` (both with/without a space after the colon). `retry` is **not** a back-off — it is a second go-signal. The loop happens only when *neither* token is present.

---

## EXCLUDED indicators — do **not** deploy these

These appeared during analysis but were ruled out. Shipping them causes false positives or wastes pivots.

| Excluded indicator | Why it's not an IOC |
|---|---|
| `The Universe Security Company Ltd` self-signed TLS cert (serial `59B1FE0A…`, fp `5d8ac9ed…`) | **Sandbox/transit MITM artifact.** Absent from all CT logs and internet scans; the domain's real cert history is exclusively public-CA DV (Let's Encrypt / Sectigo / Google Trust). |
| Cloudflare edge IPs `104.21.93.242`, `172.67.216.224` (+ IPv6 `2606:4700:*`) | Shared Cloudflare fronts. Non-durable; co-host hundreds of unrelated domains. |
| Any domain co-resolving on those Cloudflare IPs | Shared-CF-IP neighbors = noise, not a cluster. |
| `JA3` / `JA3S` hashes, TLS record sizes, "217-cycle" loop timing | Derived from the OS Schannel stack / implementation; not actor-controlled. |
| URIs `/checker`, `/checkera`, `/checknt` | Sandbox parsing artifacts; contradict the binary. Real paths are only `/register`, `/check`, `/status`, `/download/Game.*`. |
| `HiStageClient/2.0` (full string) | Strings-dump adjacency illusion (`Hi` is a MessageBoxA literal). Runtime UA is `StageClient/2.0`. |
| OpenCodeSetup "Ship Faster" decoy page; `t.me/Normalmd` ("Michael Dorian") | Commodity SaaS-lure template (10,000+ near-identical pages); Telegram traffic is the browser following the decoy, not malware C2. The loader has zero Telegram code. |
| `fa-ir` locale string, `ConsoleApplication1.pdb` | One row of the MSVC NLS table / a Visual Studio default project name. Not indicative. |

---

## ATT&CK (summary)

T1071.001 · T1105 · T1070.004 · T1059.003 · T1614.001 · T1033 · T1082 · T1083 · T1057 · T1036 · T1553.002

See `docs/ATTACK_MAPPING.md` for the per-technique evidence.
