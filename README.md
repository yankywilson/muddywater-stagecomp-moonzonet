# MuddyWater "Stagecomp" Downloader — Detection & Intelligence Pack

**TLP:CLEAR** · Author: Yanky Wilson ([github.com/yankywilson](https://github.com/yankywilson)) · 2026-06-11

Detection content and an analyst-facing assessment for a native C++ first-stage downloader ("Stagecomp") that beacons over HTTPS to **`moonzonet.com`** and is assessed — **with moderate confidence** — as **MuddyWater (Iran / MOIS)** tooling.

Everything here is built from **first-hand static reverse engineering**, with infrastructure claims cross-checked across certificate-transparency, passive-DNS, and host-scan sources. Indicators are included only where reproduced; analysis-path artifacts were identified and excluded (see below).

---

## What this is

A minimal **courier**, not a full RAT. It fingerprints the host, registers with a C2, waits for an operator "go" verdict, downloads a three-file second stage, launches it, and self-deletes. No persistence, no privilege escalation, no obfuscation.

```
MessageBox decoy → sleep → /register → poll /check
   → (on "approved":true OR "retry":true) → GET /download/Game.{dll,exe,config}
   → drop to \GameFiles\ → run Game.exe → /status → self-delete
```

---

## Attribution — read this first

Attribution to **MuddyWater is MODERATE, not confirmed.** It rests on a **single primary open source** plus dependent platform tags. Two traits cut against a clean state-APT picture: a **commodity (revoked) Microsoft Trusted Signing cert**, and a **low-grade Telegram/SaaS scam decoy** on the same domain. Treat the actor call as provisional. Full reasoning: [`docs/INTELLIGENCE_ASSESSMENT.md`](docs/INTELLIGENCE_ASSESSMENT.md).

---

## Contents

| Path | What |
|---|---|
| `detections/yara/stagecomp_downloader.yar` | YARA for the loader (config strings, imphash, hash-pin) |
| `detections/sigma/` | Sigma: self-delete, proxy C2 beacon, file drops, DNS |
| `detections/suricata/stagecomp.rules` | Suricata: DNS + TLS SNI (wire-visible); HTTP UA/URI (needs TLS inspection) |
| `detections/kql/stagecomp_hunting.kql` | Defender XDR / Sentinel hunting queries |
| `IOCs.md` | Durable indicators **+ an explicit excluded-indicator list** |
| `docs/ATTACK_MAPPING.md` | ATT&CK with per-technique evidence |
| `docs/INTELLIGENCE_ASSESSMENT.md` | ICD-203 assessment (Iran/MuddyWater context, gaps, caveats) |

---

## Strongest indicators

| Indicator | Value |
|---|---|
| C2 domain | `moonzonet.com` |
| User-Agent (substring) | `StageClient/2.0` |
| URI chain | `/register`, `/check`, `/status`, `/download/Game.{dll,exe,config}` |
| Config drop (near-unique) | `visualwincomp.txt` (in `\GameFiles\`) |
| SHA-256 | `a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0` |
| imphash | `9963ebabcee092908eac2414f7c4661a` |

---

## ⚠️ What is NOT an indicator

Do not deploy these — they are artifacts or shared infrastructure and will cause false positives or wasted pivots. (Full table with reasons in [`IOCs.md`](IOCs.md).)

- **`The Universe Security Company Ltd` self-signed TLS cert** — sandbox/transit MITM artifact; absent from all CT logs. The domain's real certs are public-CA DV only.
- **Cloudflare edge IPs** `104.21.93.242`, `172.67.216.224` (and co-hosted neighbors) — shared fronts, non-durable.
- **JA3/JA3S, TLS record sizes, "217-cycle" timing** — OS Schannel artifacts, not actor-controlled.
- **`/checker`, `/checkera`, `/checknt`** — sandbox parsing artifacts; contradicted by the binary.
- **`HiStageClient/2.0`** (full form) — strings-dump illusion; the runtime UA is `StageClient/2.0`.
- **OpenCodeSetup decoy page / `t.me/Normalmd`** — commodity lure template; the loader has no Telegram code.

---

## Usage

```bash
# YARA
yara -r detections/yara/stagecomp_downloader.yar /path/to/scan

# Sigma -> your SIEM (example: convert with sigma-cli)
sigma convert -t <backend> detections/sigma/

# Suricata
cp detections/suricata/stagecomp.rules /etc/suricata/rules/ && suricatasc -c reload-rules
```

For Defender/Sentinel, paste the queries in `detections/kql/stagecomp_hunting.kql` into advanced hunting (run individually).

**Network reality check:** C2 is HTTPS. The DNS and TLS-SNI rules work on the wire; the User-Agent and URI rules require a TLS-inspecting proxy.

---

## Notes & caveats

- **`retry` is a GO-signal, not a back-off.** The loader downloads on `"approved":true` *or* `"retry":true`. It loops only when neither is present.
- **Second stage (`Game.exe`) was not recovered** — the gate never approved in available detonations. Detection here targets the loader and C2, not the payload.
- **`WebView2Loader.dll`** and **`Game.exe`** are legitimate-sounding names — always pair them with the `\GameFiles\` path or the co-located `visualwincomp.txt`.

---

## Reference

- Rapid7, *"Muddying the Tracks,"* May 2026 (primary attribution source).

## License

Detection content released TLP:CLEAR for defensive use. Attribution appreciated.
