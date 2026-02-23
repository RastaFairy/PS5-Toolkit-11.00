<div align="center">

<br/>

```
 ██████╗ ██████╗ ██████╗ ██╗███████╗██╗  ██╗██╗████████╗
██╔═══██╗██╔══██╗██╔══██╗██║██╔════╝██║ ██╔╝██║╚══██╔══╝
██║   ██║██████╔╝██████╔╝██║███████╗█████╔╝ ██║   ██║   
██║   ██║██╔══██╗██╔══██╗██║╚════██║██╔═██╗ ██║   ██║   
╚██████╔╝██║  ██║██████╔╝██║███████║██║  ██╗██║   ██║   
 ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
```

**WebKit-based arbitrary code execution & payload injection toolkit for PS5 firmware 11.xx**

<br/>

[![Firmware](https://img.shields.io/badge/Firmware-11.00-00b4d8?style=flat-square&logo=playstation)](.)
[![Architecture](https://img.shields.io/badge/Arch-FreeBSD%20AMD64-6060a0?style=flat-square)](.)
[![Language](https://img.shields.io/badge/Lang-C%20%7C%20JS%20%7C%20Python-ffe600?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-GPLv3-00ffaa?style=flat-square)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Research-ff3c78?style=flat-square)](.)

<br/>

[Overview](#overview) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Modules](#modules) · [Contributing](#contributing) · [Credits](#credits)

<br/>

> **Español** → [README.es.md](./README.es.md)

</div>

---

## Overview

**OrbisKit** is a modular, well-documented research toolkit that chains together a series of techniques to achieve arbitrary code execution on a PlayStation 5 running firmware **11.00**, and then inject custom payloads in `.elf`, `.bin`, or `.self` format.

It is designed to be readable and educational — every file is heavily commented, every design decision is explained in `docs/`, and the exploit chain is broken into clearly separated, independently understandable modules.

### What it does

Starting from a type-confusion bug in the WebKit JavaScript engine (a variant of CVE-2021-30889 active in FW 11.x), the toolkit:

1. Builds arbitrary userland **read/write primitives** inside the WebKit process
2. Leaks `libkernel.sprx` base and constructs **ROP chains** via a Web Worker stack pivot (bypassing Clang forward-edge CFI)
3. Escalates to the **kernel** using a umtx race condition UAF + pipe trick for kernel R/W
4. Escapes the Orbis OS **Jail container**, gains **root**, disables SCEP and `kern.securelevel`
5. Installs a **persistent ELF loader** in `SceRedisServer` via ptrace — survives rest mode and browser restarts
6. Listens on **port 9021** and executes any payload sent from the host PC

### Security mitigations addressed

| Mitigation | Scope | How it is handled |
|-----------|-------|-------------------|
| SMEP | Kernel | Not triggered — no user→kernel execution |
| SMAP | Kernel | Bypassed via kernel R/W primitives |
| XOM (R^X) | User+Kernel | Gadgets sourced from libkernel data section (readable) |
| Clang-CFI (forward-edge) | User+Kernel | Not triggered — we attack the **return address** (backward-edge), not vtable pointers |
| Shadow Stack | — | **Not implemented on PS5** — our primary attack vector |
| Hypervisor / Jail | Both | Patched via `cr_prison → prison0` in the process ucred |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  HOST PC                          PS5 (FW 11.00 / Orbis OS)   │
│                                                                │
│  host/server.py ──── HTTP :8000 ──► WebKit Browser            │
│       │                                   │                    │
│       │                            exploit/js/*.js             │
│       │                            (primitives + ROP)          │
│       │                                   │                    │
│       │                            kernel.js                   │
│       │                            (kbase leak, R/W, root)     │
│       │                                   │                    │
│       │  ◄── fetch elfldr.elf ────────────┤                    │
│       │                            loader.js                   │
│       │                            (sends ELF via ROP socket)  │
│       │                                   │                    │
│       │                            SceRedisServer              │
│       │                            └─ elfldr (ptrace inject)   │
│       │                               └─ :9021 listener        │
│       │                                                        │
│  tools/send_payload.py ─ TCP :9021 ──► fork() + exec payload   │
│  tools/listen_log.py   ◄─ UDP :9998 ── broadcast logs          │
└────────────────────────────────────────────────────────────────┘
```

### Exploit chain at a glance

| Step | File | What happens |
|------|------|-------------|
| 1 | `exploit/js/primitives.js` | WebKit bug → `leakobj` / `fakeobj` → `read8` / `write8` |
| 2 | `exploit/js/rop.js` | libkernel base leak → ROPChain builder → Worker stack pivot |
| 3 | `exploit/js/kernel.js` | umtx UAF → kernel R/W → container escape → root |
| 4 | `exploit/js/loader.js` | Fetch `elfldr.elf` → ROP socket send to :9020 |
| 5 | `elfldr/pt.c` | ptrace inject into `SceRedisServer` → persistent :9021 |
| 6 | `tools/send_payload.py` | Host sends `.elf` / `.bin` / `.self` → PS5 executes |

---

## Project Structure

```
orbiskit/
│
├── README.md                    ← This file (English)
├── README.es.md                 ← Spanish version
├── LICENSE                      ← GPLv3
├── CHANGELOG.md                 ← Version history
├── CONTRIBUTING.md              ← How to contribute
├── SECURITY.md                  ← Vulnerability disclosure policy
├── CODE_OF_CONDUCT.md           ← Community standards
│
├── exploit/                     ← Served to the PS5 browser
│   ├── index.html               ← Orchestrator UI (5-phase progress bar)
│   └── js/
│       ├── int64.js             ← 64-bit integer arithmetic helper
│       ├── offsets_1100.js      ← All FW 11.00 offsets (libkernel, WebKit, kernel)
│       ├── primitives.js        ← Userland R/W via victim ArrayBuffer trick
│       ├── rop.js               ← ROPChain builder + Worker stack pivot
│       ├── kernel.js            ← Kernel escalation (kbase, R/W, root, escape)
│       └── loader.js            ← Fetches and sends elfldr.elf via ROP socket
│
├── elfldr/                      ← ELF Loader (C, compile with ps5-payload-sdk)
│   ├── main.c                   ← TCP listener on :9021, fork() per payload
│   ├── elfldr.c / elfldr.h      ← ELF64/SELF/RAW parser, mmap, mprotect
│   ├── pt.c / pt.h              ← ptrace bootstrap into SceRedisServer
│   └── Makefile
│
├── host/
│   └── server.py                ← HTTP server (COOP/COEP headers + /probe endpoint)
│
├── tools/
│   ├── send_payload.py          ← Send .elf / .bin / .self to PS5 port 9021
│   └── listen_log.py            ← Receive UDP logs from the PS5 loader
│
├── payload/example/
│   ├── hello.c                  ← Minimal example payload
│   └── Makefile
│
├── payloads/                    ← Drop your compiled payloads here
│
└── docs/
    ├── architecture.md          ← Deep technical write-up
    └── offsets_guide.md         ← How to find offsets with Ghidra for other FWs
```

---

## Quick Start

### Requirements

**On your PC:**
- Python 3.8+
- `ps5-payload-sdk` (to recompile the C loader if needed)
- Ghidra + PS5 script (to find offsets — see `docs/offsets_guide.md`)
- Same LAN/Wi-Fi segment as the PS5

**On the PS5:**
- Firmware **11.00** (exactly — do not update)
- Active network connection
- Access to the built-in WebKit browser

---

### Step-by-step

**1. Clone and configure**

```bash
git clone https://github.com/YOUR_USERNAME/orbiskit
cd orbiskit

# Set your PC's local IP address in two places:
nano exploit/js/loader.js     # HOST_IP = "192.168.1.X"
nano payload/example/hello.c  # PC_IP   = "192.168.1.X"
```

**2. Start the HTTP server on your PC**

```bash
python3 host/server.py
# Output will show the exact URL to open on the PS5
# → http://192.168.1.X:8000/exploit/index.html
```

**3. Open the exploit page on the PS5**

On the PS5, navigate to the URL shown above in the built-in browser.  
Press **▶ Run exploit** and wait for all 5 phases to complete.

**4. (Optional) Watch logs in real time**

```bash
# In a second terminal on the PC:
python3 tools/listen_log.py
```

**5. Send a payload**

```bash
python3 tools/send_payload.py --host 192.168.1.50 --file payloads/my_payload.elf

# Supported formats (auto-detected by magic bytes):
#   .elf  → ELF64 native (magic: \x7fELF)
#   .self → Sony signed SELF (magic: \x00PSF)
#   .bin  → Raw binary (any other)
```

**6. Compile the ELF loader (if you modify it)**

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make -C elfldr/
cp elfldr/elfldr.elf payloads/
```

---

## Modules

| Module | Language | Description |
|--------|----------|-------------|
| `int64.js` | JS | 64-bit arithmetic (hi/lo pair), float↔int64 conversion for pointer work |
| `offsets_1100.js` | JS | All FW 11.00 offsets: gadgets, pthread struct, kernel fields |
| `primitives.js` | JS | `Primitives` class — victim ArrayBuffer read8/write8/readBytes/writeBytes |
| `rop.js` | JS | `ROPChain` fluent builder, `findWorkerStack()`, `launchROPChain()` |
| `kernel.js` | JS | `KernelExploit` — kbase leak, kernel R/W, jail escape, root, SCEP disable |
| `loader.js` | JS | `PayloadLoader` — fetch + ROP socket send + /probe polling |
| `elfldr/main.c` | C | TCP server, connection handling, UDP log broadcast |
| `elfldr/elfldr.c` | C | ELF64 parser, PT_LOAD mapping, RELA relocations, SELF extraction |
| `elfldr/pt.c` | C | ptrace attach, shellcode injection, RIP redirect, detach |
| `host/server.py` | Python | HTTP + COOP/COEP headers, /probe endpoint, /status |
| `tools/send_payload.py` | Python | Type detection, ELF validation, progress bar, connectivity check |
| `tools/listen_log.py` | Python | UDP broadcast receiver with timestamps and color coding |

---

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| Scaffold & architecture | ✅ Complete | All files, interfaces, and documentation in place |
| `Int64` + `Primitives` classes | ✅ Complete | Connects to any `leakobj/fakeobj` source |
| `ROPChain` builder | ✅ Complete | Full syscall support, Worker pivot |
| `KernelExploit` | ✅ Complete | All four sub-phases implemented |
| ELF loader (C) | ✅ Complete | ELF64, SELF extraction, RAW, fork model |
| ptrace bootstrap | ✅ Complete | SceRedisServer injection chain |
| Host tools | ✅ Complete | server.py, send_payload.py, listen_log.py |
| FW 11.00 offsets | ⚠️ Verify | Values in `offsets_1100.js` need validation against a real FW 11.00 dump |
| `triggerWebKitBug()` | ❌ TODO | Requires binary analysis of FW 11.00 WebKit — the only missing link |
| `leakLibKernelBase()` | ❌ TODO | Requires a known GOT pointer from WebKit binary |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting a pull request.

Key areas where help is needed:
- Identifying the active WebKit bug for FW 11.00 (`triggerWebKitBug()`)
- Verifying and correcting offsets in `offsets_1100.js`
- Porting to adjacent firmware versions

---

## Security

Please read [SECURITY.md](./SECURITY.md) for the responsible disclosure policy.  
Do **not** open public issues for unpatched vulnerabilities.

---

## Legal Disclaimer

This project is intended **solely for security research and educational purposes**.  
Use it only on hardware you own and are legally authorized to test.  
The authors assume no responsibility for any misuse.

---

## Credits

OrbisKit builds on publicly documented techniques and prior work by:

| Researcher | Contribution |
|-----------|-------------|
| **ChendoChap & Znullptr** | WebKit ROP execution, PS5 CFI analysis |
| **john-tornblom** | ps5-payload-elfldr, ps5-payload-sdk |
| **SpecterDev** | PS5-IPV6-Kernel-Exploit, PSFree |
| **sleirsgoevy** | Original WebKit bug PoC |
| **idlesauce** | umtx2 webkit jailbreak framework |
| **abc** | PSFree 150b |
| **shahrilnet & n0llptr** | umtx lua implementation |

---

<div align="center">
<sub>Licensed under GPLv3 · For research use only · PS5 is a trademark of Sony Interactive Entertainment</sub>
</div>
