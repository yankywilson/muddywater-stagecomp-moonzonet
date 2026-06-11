# Technical Analysis — Stagecomp Downloader

**TLP:CLEAR** · Author: Yanky Wilson ([github.com/yankywilson](https://github.com/yankywilson)) · 2026-06-11

First-hand static reverse engineering of the MuddyWater "Stagecomp" first-stage downloader. Every indicator and detection rule in this repo derives from the analysis below. Work was performed **air-gapped and passively** — the C2 was never contacted directly.

---

## 1. Sample identity

| Property | Value |
|---|---|
| SHA-256 | `a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0` |
| SHA-1 | `0ba2306ec15f7124fafc7615e81f34c7986ba9a5` |
| MD5 | `7f3c8a7fe78d3d05b6022df3ea0c15fb` |
| imphash | `9963ebabcee092908eac2414f7c4661a` |
| File type | PE32 executable, i386, **Console** subsystem |
| Language | Native **C++** (MSVC 19.29 / Visual Studio 2019) |
| Size | 307,656 bytes |
| Packed? | **No** — normal section entropy, clean imports, no unpacking stub |
| Observed names | `DIDS.exe`, `JnDqkL6jrT.exe` |
| Compiled | 2026-02-14 |
| Code-signed | 2026-02-17 — abused Microsoft Trusted Signing cert ("Donald Gay"), since revoked |

**What it is:** a **courier/downloader**, not the full RAT. It fingerprints the host, registers with C2, waits for an operator verdict, pulls and runs a second stage, then deletes itself.

---

## 2. Methodology & tooling

| Stage | Tool | Purpose |
|---|---|---|
| Triage | CFF Explorer | PE structure, imports, version-info, manifest |
| Hand RE | **Ghidra** | full control-flow recovery of the worker + helpers |
| Capability cross-check | CAPA | independent confirmation of behaviors / ATT&CK |
| String/obfuscation check | FLOSS | confirm there is **no** string obfuscation |

Approach: recovery-first and **validation-gated** — a behavior was accepted only when reproduced by hand and not contradicted by CAPA/FLOSS. Tooling artifacts were identified and discarded rather than promoted to indicators (see §9).

---

## 3. Kill chain (verified end to end)

```
MessageBoxA("Hi", ":)")            decoy popup
   → FreeConsole()                 detach console
   → Sleep(~45s)                   delay
   → WinHttpOpen(L"StageClient/2.0")
   → [host fingerprint]            FUN_00401150
   → POST /register                FUN_00401210
   → do {
        POST /check                FUN_00401210
        gate(resp)                 FUN_004016b0 / FUN_004016e0  (strstr)
        if NOT ("approved":true OR "retry":true):
            re-register; Sleep(15s); continue
     } while (not approved)
   → GET /download/Game.dll         FUN_004013b0
   → GET /download/Game.exe
   → GET /download/Game.config
   → write WebView2Loader.dll, Game.exe, visualwincomp.txt
        into <Downloads>\GameFiles  (fallback C:\Users\Public\Downloads)
   → CreateProcessA("Game.exe")
   → POST /status (success)         FUN_00401340
   → self-delete                    FUN_004017f0
   → ExitProcess
```

---

## 4. Function map

| Address | Role | Key behavior |
|---|---|---|
| `FUN_00401900` | **Main worker** | orchestrates the whole kill chain above |
| `FUN_00401150` | Host fingerprint | `GetComputerNameA` → `GetUserNameA` → domain from `%USERDOMAIN%` (else `WORKGROUP`); any failure → `Unknown` |
| `FUN_00401210` | **HTTP POST engine** | `WinHttpConnect` host `moonzonet.com` port 443, `WINHTTP_FLAG_SECURE`, header `Content-Type: application/json` |
| `FUN_004013b0` | Downloader | issues the three `GET /download/Game.*` requests, writes bytes to disk |
| `FUN_00401340` | Status reporter | `POST /status` with tokens `downloading` / `error` / `running` / `success` / `EXIT_%lu` / `RUN_%lu` |
| `FUN_004016b0`, `FUN_004016e0` | Gate predicates | thin `strstr` wrappers used to test the C2 verdict tokens |
| `FUN_004017f0` | Self-delete | builds and runs the ping-delay delete via hidden `CreateProcessW` |

---

## 5. C2 protocol

**Transport:** WinHTTP over HTTPS:443, User-Agent **`StageClient/2.0`**, `Content-Type: application/json`.

**Beacon identity:** `client_id = <ComputerName>_<UserName>_<TickCount>`.

**Request sequence:**

| Method | Path | Body (templates) |
|---|---|---|
| POST | `/register` | `{"client_id":"%s","computer_name":"%s","username":"%s","domain":"%s"}` |
| POST | `/check` | `{"client_id":"%s"}` |
| GET | `/download/Game.dll`, `/download/Game.exe`, `/download/Game.config` | — |
| POST | `/status` | `{"client_id":"%s","status":"%s","error_code":"%s"}` |

**The gate — important.** The loop proceeds to download when the `/check` response contains **either** `"approved":true` **or** `"retry":true` (both with and without a space after the colon). `retry` is **not** a back-off — it is a second go-signal. The loader only loops (re-register → sleep 15s) when **neither** token is present. This is server-side targeting: operators can keep the payload from sandboxes and non-targets simply by never returning a go-token, which is why the second stage stays out of public feeds.

The payload layer (`Game.*` contents) is **opaque** — the request structure is fully recovered, but the second-stage bytes were never served in any available detonation.

---

## 6. Host fingerprinting (FUN_00401150)

Collects computer name, user name, and domain. Domain resolves from the `%USERDOMAIN%` environment variable; if absent it falls back to the literal `WORKGROUP`. Any API failure substitutes the literal `Unknown`. These literals appear in beacon bodies and are weak indicators on their own (documented but not used as primary IOCs).

The **only registry operation** in the entire binary is a read of `…\NLS\Language` (System Language Discovery, **T1614.001**) — there is no persistence write, no Run key, nothing else.

---

## 7. Staging & execution

Three files are written into a `GameFiles` subfolder under the user's Downloads (or `C:\Users\Public\Downloads` when no per-user path resolves):

| Server object | Written as | Note |
|---|---|---|
| `Game.dll` | `WebView2Loader.dll` | sideload name; masquerades as the legitimate Microsoft DLL |
| `Game.exe` | `Game.exe` | second stage (referred to in source reporting as a trojanized WebView2 sample) |
| `Game.config` | `visualwincomp.txt` | config; **near-unique filename** and the best disk indicator |

Execution is a plain `CreateProcessA("Game.exe")`. No injection, no LOLBin chain.

---

## 8. Self-deletion (FUN_004017f0)

On a clean success path the loader removes its own image:

```
cmd.exe /c ping 127.0.0.1 -n 6 > nul && del /f /q "<self path>"
```

Launched via `CreateProcessW` with a hidden window. The `ping -n 6` is a ~5-second delay so the parent exits before the delete. This is a **weak/generic** technique (T1070.004 + T1059.003) and fires **only on the success branch** — in no available detonation did the gate approve, so it was never observed dynamically (consistent with `Game.exe` never dropping).

---

## 9. Notable absences and calibration corrections

The *absence* of capability is itself a finding — this is a minimal courier, not a RAT.

| Not present | Confirmed by |
|---|---|
| Persistence (no Run key, service, task) | hand RE — launch-and-exit only |
| Privilege escalation | manifest `asInvoker`, no UAC prompt |
| Mutex / single-instance | no `CreateMutex` |
| String obfuscation | **FLOSS null**: 1 stack string (`@\Downloads`), 1 "decoded" (`Unknown`) — i.e. plaintext |
| Packing | normal entropy, clean imports |

**Corrections made during analysis (do not regress):**

- **User-Agent is `StageClient/2.0`, not `HiStageClient/2.0`.** The `Hi` is a `MessageBoxA` literal that sits adjacent to the UA string in a raw strings dump; runtime memory shows the exact header `User-Agent: StageClient/2.0`. Anchor on the substring.
- **`/checker`, `/checkera`, `/checknt` are sandbox parsing artifacts** that contradict the decompiled request paths. The real paths are only `/register`, `/check`, `/status`, `/download/Game.*`.
- **CAPA's `B0013.001` "analysis-tool discovery" is a likely false positive** driven by locale-table strings; no such logic exists in the binary.
- FLOSS incidentally surfaced a timestamp-authority ESN (`nShield TSS ESN:7800-05E0-D9471503`) consistent with the code-signing countersignature — context, not an IOC.

---

## 10. What was not determined

- **Second-stage `Game.exe`** — never served (gate never approved); not recovered from any public feed.
- **C2-side payload logic** — opaque; only the client request structure is known.
- **Initial-access vector** — out of scope for this downloader; this sample sits downstream of delivery.

---

## 11. ATT&CK

See [`ATTACK_MAPPING.md`](ATTACK_MAPPING.md) for per-technique evidence tied to the functions above.
