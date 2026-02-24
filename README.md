# PS5-Toolkit — WebKit Research Scaffold for FW 11.xx

> **Español** → [README_ES.md](README_ES.md)  
> **Non-developers** → [docs/GUIDE_NONTECHNICAL.md](docs/GUIDE_NONTECHNICAL.md)  
> **Full technical honesty** → [HONEST_LIMITATIONS.md](HONEST_LIMITATIONS.md)

---

## Before anything else

This project is **not a working exploit**. It is a documented research scaffold.

Several projects circulating in the PS5 community present code structured like this
as functional exploits. They are not, and neither is this one. The difference here
is that we document exactly what is missing and why, rather than obscuring it.

**If a project claims to be a working FW 11.xx WebKit exploit and does not show you
a video of it running on real hardware — assume it has the same holes this one does.**

The full breakdown of what is broken and why is in [HONEST_LIMITATIONS.md](HONEST_LIMITATIONS.md).

---

## What this project actually contains

A complete, architecturally correct scaffold for a WebKit-based exploit chain on
PlayStation 5 firmware 11.xx. Every module is implemented **except the pieces that
require binary analysis of a real FW 11.00 dump**:

| Component | State | What blocks it |
|---|---|---|
| `triggerWebKitBug()` | ❌ TODO | FW 11.00 WebKit binary analysis |
| `leakLibKernelBase()` | ❌ TODO | GOT pointer from FW 11.00 WebKit binary |
| All ROP gadget offsets | ❌ `0x0` | `libkernel_web.sprx` extraction + ROPgadget |
| `_pipeRead8/Write8` | ❌ Empty stubs | `pipe_buffer` layout from kernel binary |
| `_ropMmap()` | ❌ Returns `0x0` | `mov [mem], rax` gadget offset |
| `pt.c` spin-wait | ⚠️ Unreliable | `nanosleep`/`sched_yield` offsets |
| ELF64 parser (`elfldr.c`) | ✅ Functional | No firmware dependency |
| `int64.js` | ✅ Functional | No firmware dependency |
| Host tools | ✅ Functional | No firmware dependency |
| ROP chain builder logic | ✅ Correct | Blocked only by missing offsets |
| Kernel escalation logic | ✅ Correct | Blocked only by missing primitives |

The single root cause for everything in that table is the same:
**`offsets_1100.js` has every critical value set to `0x00000000`** because
those values require a decrypted firmware dump that this project does not have.

---

## Technical corrections vs. prior circulating code

### ❌ No JIT in the PS5 browser

The PS5 browser launches WebKit with `ENABLE_JIT=OFF`. There is no JIT compiler,
no DFG tier, no FTL tier. Any project describing a "DFG JIT type confusion" exploit
targeting the PS5 browser is technically wrong by definition.

> Confirmed in PS4 source code at ps4-oss.com from FW 6.00 onwards.

### ❌ SharedArrayBuffer is disabled

`new SharedArrayBuffer()` throws in the PS5 browser. This project uses plain
`ArrayBuffer` objects and `performance.now()` for timing. No `Atomics` anywhere.

### ❌ Not V8

The PS5 uses JavaScriptCore (JSC), not V8. V8-specific techniques — TurboFan,
Liftoff, Sparkplug, V8 heap layout — are irrelevant here.

### ✅ What is actually correct

- Engine: JavaScriptCore (JSC), interpreter-only (LLInt)
- Exploitation primitive: ArrayBuffer length/pointer corruption via JSC type confusion
- Code execution: ROP-only, gadgets sourced from `libkernel_web.sprx`
- Timing: `performance.now()` / `Date.now()` delta loops
- Architecture: FreeBSD AMD64 (Orbis OS)

---

## What the exploit chain does (when complete)

Starting from a type confusion in JSC (same class as CVE-2021-30889, active in FW 11.x):

1. **Userland R/W** — corrupt an ArrayBuffer's backing store pointer → `read8`/`write8`
2. **libkernel base leak** — read a GOT entry in WebKit pointing into libkernel
3. **ROP chain** — gadget chain via Web Worker stack pivot, bypassing Clang forward-edge CFI
4. **Kernel escalation** — umtx UAF → pipe trick kernel R/W → root → jail escape
5. **Persistent loader** — ptrace inject into `SceRedisServer` → TCP listener on port 9021
6. **Payload execution** — send `.elf`/`.bin`/`.self` from PC, PS5 executes it

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  HOST PC                         PS5 (FW 11.00 / Orbis OS) │
│                                                             │
│  host/server.py ─── HTTP :8000 ──► WebKit Browser          │
│       │                                  │                  │
│       │                           exploit/js/*.js           │
│       │                                  │                  │
│       │                           kernel.js                 │
│       │                           (kbase, R/W, root)        │
│       │                                  │                  │
│       │  ◄── fetch elfldr.elf ───────────┤                  │
│       │                           loader.js                 │
│       │                                  │                  │
│       │                           SceRedisServer            │
│       │                           └─ elfldr :9021           │
│       │                                                      │
│  tools/send_payload.py ─ TCP :9021 ──► fork() + exec        │
│  tools/listen_log.py   ◄─ UDP :9998 ── broadcast logs       │
└──────────────────────────────────────────────────────────────┘
```

---

## Project structure

```
PS5-Toolkit/
│
├── README.md                     ← This file (English)
├── README_ES.md                  ← Spanish version
├── HONEST_LIMITATIONS.md         ← Detailed breakdown of what is broken and why
│
├── docs/
│   ├── GUIDE_NONTECHNICAL.md     ← For non-developers (EN/ES)
│   ├── architecture.md           ← Deep technical write-up (EN/ES)
│   └── offsets_guide.md          ← How to find offsets with Ghidra (EN/ES)
│
├── exploit/
│   ├── index.html                ← Exploit UI served to PS5 browser
│   └── js/
│       ├── int64.js              ← 64-bit integer helpers            ✅
│       ├── offsets_1100.js       ← FW 11.00 offsets (all 0x0)       ❌
│       ├── primitives.js         ← triggerWebKitBug() stub           ❌
│       ├── rop.js                ← leakLibKernelBase() stub          ❌
│       ├── kernel.js             ← Kernel logic ✅ — pipe R/W stubs  ❌
│       └── loader.js             ← ELF delivery — missing gadgets    ❌
│
├── elfldr/
│   ├── main.c                    ← TCP listener :9021                ✅
│   ├── elfldr.c / elfldr.h       ← ELF64/SELF/RAW parser            ✅
│   ├── pt.c / pt.h               ← ptrace injection ✅ spin-wait     ⚠️
│   └── Makefile
│
├── host/
│   └── server.py                 ← HTTP server                       ✅
│
└── tools/
    ├── send_payload.py           ← Send payloads to PS5              ✅
    └── listen_log.py             ← Receive UDP logs                  ✅
```

---

## How to contribute

The most valuable contribution is filling in `offsets_1100.js`.

If you have access to a FW 11.00 dump and have done any of the following,
a pull request with verified values is more useful than anything else:

- Identified a JSC type confusion bug active in FW 11.00 WebKit
- Found a `libkernel_web.sprx` GOT pointer in the WebKit binary
- Run ROPgadget against `libkernel_web.sprx` for FW 11.00
- Identified `pipe_buffer` struct offsets in the FW 11.00 kernel
- Found `proc`/`ucred`/`prison` struct offsets in FW 11.00

See [docs/offsets_guide.md](docs/offsets_guide.md) for the step-by-step Ghidra workflow.

---

## Credits

| Researcher | Contribution |
|---|---|
| ChendoChap & Znullptr | WebKit ROP execution, PS5 CFI analysis |
| john-tornblom | ps5-payload-elfldr, ps5-payload-sdk |
| SpecterDev | PS5-IPV6-Kernel-Exploit, PSFree |
| sleirsgoevy | Original WebKit bug PoC |
| idlesauce | umtx2 webkit jailbreak framework |
| abc | PSFree 150b |
| shahrilnet & n0llptr | umtx lua implementation |

---

*Licensed GPLv3 · Research use only · PlayStation 5 is a trademark of Sony Interactive Entertainment*
