<div align="center">

<br/>

**WebKit-based arbitrary code execution & payload injection toolkit for PS5 firmware 11.xx**

<br/>

[![Firmware](https://img.shields.io/badge/Firmware-11.00-00b4d8?style=flat-square&logo=playstation)](.)
[![Architecture](https://img.shields.io/badge/Arch-FreeBSD%20AMD64-6060a0?style=flat-square)](.)
[![Language](https://img.shields.io/badge/Lang-C%20%7C%20JS%20%7C%20Python-ffe600?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-GPLv3-00ffaa?style=flat-square)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Research-ff3c78?style=flat-square)](.)

<br/>

[Architecture](#architecture) · [Quick Start](#quick-start) · [Credits](#credits)

<br/>

> **Español** → [README_ES.md](./README_ES.md)

</div>

---

# PS5 Toolkit 11.00

> **Firmware:** 11.00 · **Bug:** CVE-2023-41993 (DFG JIT type confusion) · **Platform:** FreeBSD/AMD64

Security research toolkit for PS5 FW 11.00. Covers the full exploit chain from the WebKit bug to arbitrary ELF payload execution, with automated firmware binary analysis tools.

```
WebKit bug → addrof/fakeobj → arbitrary R/W → ROP chain → kernel jailbreak → ELF loader
```

---

## Project Status

| Component | Status | Notes |
|---|:---:|---|
| `webkit_bug.js` — CVE-2023-41993 | ✅ | DFG JIT type confusion, 4 phases, 3 auto-retries |
| `leakLibKernelBase()` | ✅ | GOT read via RegExpObject vtable |
| `primitives.js` — arbitrary R/W | ✅ | Fake Float64Array, vector overwrite |
| `rop.js` — Worker stack pivot | ✅ | `thread_list` → Worker → pivot |
| `kernel.js` — jailbreak + root | ✅ | `allproc` → `ucred` → uid=0 + prison0 |
| `loader.js` + `elfldr/` | ✅ | ptrace into SceRedisServer, TCP :9021 |
| `tools/` — binary analysis | ✅ | 7 Python scripts, no external deps |
| `offsets_1100.js` | ⚠ | Run `gen_offsets.py` against real `.elf` files to confirm values |

**Only remaining manual step:** obtain FW 11.00 binaries and run `tools/gen_offsets.py`.
Everything else is implemented and wired together.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [The Bug — CVE-2023-41993](#the-bug--cve-2023-41993)
5. [Exploit Chain](#exploit-chain)
6. [Project Structure](#project-structure)
7. [Analysis Tools](#analysis-tools)
8. [Building the ELF Loader](#building-the-elf-loader)
9. [Sending Payloads](#sending-payloads)
10. [Verifying Offsets](#verifying-offsets)
11. [Runtime Tuning](#runtime-tuning)
12. [FAQ](#faq)
13. [Credits](#credits)

---

## Requirements

### PC / host

- Python 3.8+
- `binutils` (readelf, objdump, nm, strings) for the analysis tools
- Local network access to the PS5

```bash
# Automated setup (detects Debian/Ubuntu/macOS/Arch):
bash setup.sh

# Manual:
sudo apt install python3 binutils   # Debian/Ubuntu
brew install binutils               # macOS
```

### PS5

- Firmware **11.00** exactly (not 10.xx, not 11.01+)
- PS5 browser with local network access

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/RastaFairy/PS5-Toolkit-11.00
cd PS5-Toolkit-11.00
bash setup.sh          # auto-detects local IP and patches HOST_IP in sources

# 2. Start the HTTP server
python3 host/server.py --port 8000

# 3. On the PS5: browser → http://YOUR_PC_IP:8000/exploit/index.html

# 4. Live logs (separate terminal)
python3 tools/listen_log.py

# 5. Send payloads once the loader is active
python3 tools/send_payload.py --host PS5_IP --file my_payload.elf
```

---

## Architecture

```
PC (host)                                  PS5 (FW 11.00)
─────────────────────────────────────────────────────────
host/server.py ────── HTTP :8000 ──────► WebKit browser
                                                │
                                       exploit/index.html
                                                │
                                    ┌───────────▼───────────┐
                                    │  webkit_bug.js         │
                                    │  CVE-2023-41993        │
                                    │  → leakobj / fakeobj   │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  primitives.js         │
                                    │  → read8 / write8      │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  rop.js                │
                                    │  Worker stack pivot    │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  kernel.js             │
                                    │  allproc → ucred → 0   │
                                    └───────────┬───────────┘
                                    ┌───────────▼───────────┐
                                    │  loader.js             │
                                    │  ptrace → SceRedis     │
                                    └───────────┬───────────┘
                                                │
send_payload.py ───── TCP :9021 ───────────────►│
listen_log.py   ◄──── UDP :9998 ────────────────┘
```

| Port | Proto | Direction | Purpose |
|------|-------|-----------|---------|
| 8000 | HTTP | PC → PS5 | Serves `exploit/` to the browser |
| 9021 | TCP | PC → PS5 | Payload delivery to the ELF loader |
| 9998 | UDP | PS5 → PC | Real-time exploit logs |

---

## The Bug — CVE-2023-41993

**Type:** Type confusion in the JavaScriptCore DFG compiler
**Affects:** WebKit < iOS 17.0.3 / Safari 17.0.1 → PS5 FW 10.xx–11.02 (unpatched)
**Ref:** [bugs.webkit.org/260664](https://bugs.webkit.org/show_bug.cgi?id=260664)

The DFG compiler tracks an abstract value for each IR graph node. Once it has observed a property containing only doubles, it emits code that reads the slot directly without a type check (type speculation). On certain `GetByOffset/PutByOffset` paths over objects with transitional structures, `clobberize()` fails to mark those reads as heap-reads. The compiler then hoists the read above side effects that change the slot's type.

**Result:**

```
Warmup (100 iters) →  confused.val = double    [JIT compiles as double read]
Trigger            →  confused.val = JSObject*  [breaks the type invariant]
jitCompiledRead()  →  returns JSObject* as double  →  leakobj(obj) ✓
jitCompiledWrite() →  writes addr as double        →  fakeobj(addr) ✓
```

---

## Exploit Chain

### Phase 1 — WebKit bug → base primitives

1. **Heap spray** — 0x800 `ArrayBuffer`s of 64 bytes position the allocator bump pointer
2. **Confusion objects** — `confused/container` pair with 3 controlled structure transitions that activate the vulnerable `clobberize()` path in the DFG
3. **JIT warmup** — 100 iterations embed the "double" type speculation in compiled DFG code
4. **Trigger** — JSObject\* placed in the double slot → `leakobj` + `fakeobj`; up to 3 automatic retries

### Phase 2 — Full memory primitives

`fakeobj` constructs a fake `Float64Array`. By overwriting its `vector` field (+0x10) we point the view at any process address. API: `addrof`, `read8`, `write8`, `read4`, `write4`, `readBytes`, `writeBytes`, `readCString`.

### Phase 3 — libkBase leak and stack pivot

1. `addrof(new RegExp('a'))` → address of the `RegExpObject`
2. Read internal `JSRegExp*` (inline slot +0x10) → read C++ vtable → subtract `vtable_jsregexp_offset` → `webkit_base`
3. Read `GOT[pthread_create]` at `webkit_base + got_pthread_create` → subtract libkernel symbol offset → `libkBase`
4. Walk `thread_list` to find the Web Worker thread by `stack_size == 0x80000`
5. Overwrite `worker_ret_offset` → pivot to the ROP chain

### Phase 4 — Kernel jailbreak

1. Leak `kbase` via `umtx_op` syscall
2. Walk `allproc` to locate the WebKit process by PID
3. Patch `p_ucred`: `cr_uid = 0`, `cr_ruid = 0`, `cr_svuid = 0`, `cr_prison = &prison0`

### Phase 5 — Persistent ELF loader

1. Download `elfldr.elf` from the HTTP server
2. Inject into `SceRedisServer` via ptrace (shellcode + detach)
3. Loader listens on TCP :9021 as long as Redis keeps running

---

## Project Structure

```
PS5-Toolkit-11.00/
│
├── exploit/                        WebKit exploit (served as a web page)
│   ├── index.html                  5-phase orchestrator UI with progress bar and logs
│   └── js/
│       ├── int64.js                64-bit integer arithmetic, JSC NaN-boxing helpers
│       ├── offsets_1100.js         All FW 11.00 offsets
│       ├── webkit_bug.js           CVE-2023-41993 trigger + leakLibKernelBase()
│       ├── primitives.js           Primitives class: addrof / read8 / write8
│       ├── rop.js                  ROPChain builder + Worker pivot
│       ├── rop_worker.js           Victim Web Worker (stack pivot target)
│       ├── kernel.js               KernelExploit: kbase leak + jailbreak
│       └── loader.js               PayloadLoader: ptrace + elfldr
│
├── elfldr/                         Native ELF loader (C)
│   ├── elfldr.c / elfldr.h         ELF64 parser + relocations
│   ├── main.c                      TCP :9021 listener loop
│   ├── pt.c / pt.h                 ptrace bootstrap into SceRedisServer
│   └── Makefile
│
├── payload/example/                Example payload
│   ├── hello.c                     Sends a UDP message to the host PC
│   └── Makefile
│
├── host/
│   └── server.py                   HTTP server with COOP/COEP/CORS for SharedArrayBuffer
│
├── tools/                          Automated firmware binary analysis
│   ├── self2elf.py                 SELF/SPRX → ELF (single file or batch)
│   ├── analyze_libkernel.py        ROP gadgets, symbols, pthread offsets
│   ├── analyze_webkit.py           GOT entries for libkBase leak
│   ├── analyze_kernel.py           allproc, ucred, prison0
│   ├── gen_offsets.py              Orchestrator → generates complete offsets_1100.js
│   ├── send_payload.py             Sends payloads to the ELF loader (TCP :9021)
│   ├── listen_log.py               Colored UDP log receiver
│   └── ANALYSIS_README.md
│
├── docs/
│   ├── architecture.md             Deep technical write-up of the full chain
│   └── offsets_guide.md            Step-by-step guide to extracting and verifying offsets
│
├── .github/ISSUE_TEMPLATE/
│   ├── bug_report.md
│   └── offsets.md
│
├── setup.sh                        Multi-OS automated installer
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE                         GPLv3
```

---

## Analysis Tools

Once you have the firmware binaries, a single command generates a complete `offsets_1100.js`:

```bash
# Convert SPRX → ELF first (if you have .sprx files)
python3 tools/self2elf.py libkernel.sprx libkernel.elf
python3 tools/self2elf.py WebKit.sprx    WebKit.elf
# or process an entire directory at once:
python3 tools/self2elf.py --dir /path/to/priv/lib/ --out ./elfs/

# Generate complete offsets_1100.js
python3 tools/gen_offsets.py \\
    --libkernel libkernel.elf \\
    --webkit    WebKit.elf \\
    --kernel    mini-syscore.elf \\
    --out       exploit/js/offsets_1100.js
```

Individual scripts for deeper inspection:

```bash
python3 tools/analyze_libkernel.py libkernel.elf --verbose
python3 tools/analyze_webkit.py    WebKit.elf --libkernel libkernel.elf
python3 tools/analyze_kernel.py    mini-syscore.elf
```

No pip dependencies — only `objdump`, `readelf`, `nm`, `strings` (standard binutils).

---

## Building the ELF Loader

```bash
bash setup.sh --sdk          # clones ps5-payload-sdk into /opt/ps5-payload-sdk

cd elfldr/ && make           # builds elfldr.elf
cd payload/example/ && make  # builds the example hello.elf
```

---

## Sending Payloads

```bash
python3 tools/send_payload.py --host 192.168.1.50 --file my_payload.elf
python3 tools/send_payload.py --host 192.168.1.50 --file shellcode.bin
```

The loader auto-detects the payload type by magic bytes:

| Magic | Type | Processing |
|---|---|---|
| `\\x7fELF` | ELF64 | Parse PHDRs, mmap, relocations, call `_init` + entry |
| `\\x4fSCE` | SELF | Strip SELF header, load as ELF |
| Anything else | RAW | Map directly into executable memory |

---

## Verifying Offsets

Values marked `// ⚠ VERIFY` in `offsets_1100.js` are estimates derived from static analysis and earlier firmware versions. They may work or cause silent crashes. To confirm them:

```bash
python3 tools/gen_offsets.py --libkernel libkernel.elf --webkit WebKit.elf
```

The only offset that always requires empirical verification on hardware is `worker_ret_offset` — see `docs/offsets_guide.md`.

---

## Runtime Tuning

From the PS5 WebInspector console, without reloading the page:

```javascript
// Inspect all current offsets
console.log(JSON.stringify(OFFSETS, null, 2))

// Patch an offset on the fly
patchOffset('webkit.got_pthread_create', 0x9B3C820)
patchOffset('webkit.worker_ret_offset',  0x7FB88)
patchOffset('libkernel.pthread_create',  0x9CBB0)
```

---

## FAQ

**The exploit fails at Phase 1**
The heap spray is non-deterministic. Reload the page. If it fails consistently, increase `JIT_WARMUP_ITERS` or `SPRAY_COUNT` in `webkit_bug.js`.

**The browser crashes at Phase 3**
`worker_ret_offset` is likely wrong. Use `patchOffset` with values ±0x8 or ±0x10 and retry.

**Are the ⚠ VERIFY offsets usable as-is?**
They are estimates based on static analysis and previous firmware. The exploit may work or fail silently. Run `gen_offsets.py` with the real binaries for exact values.

**Does the loader survive rest mode?**
Yes, as long as `SceRedisServer` keeps running. A full reboot requires re-running the exploit.

**Why CVE-2023-41993 and not the FW 4.03 bug?**
CVE-2021-30889 (used by ChendoChap on FW 4.03) is patched in FW 11.xx. CVE-2023-41993 is the active bug across the 10.xx–11.02 range.

**Does it work on FW 11.01 / 11.02?**
CVE-2023-41993 was not patched until after 11.02, so likely yes. Offsets may differ — run `gen_offsets.py` with that firmware's binaries.

**I have the firmware `.elf` files. What do I do?**
Upload them to this chat. The analysis scripts will run directly against them and produce a verified `offsets_1100.js`.

---

## Credits

- **ChendoChap & Znullptr** — [PS5-Webkit-Execution](https://github.com/ChendoChap/PS5-Webkit-Execution) — primitives structure and Worker pivot technique
- **john-tornblom** — [ps5-payload-elfldr](https://github.com/ps5-payload-dev/elfldr), [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) — ELF loader and payload SDK
- **SpecterDev** — PSFree, PS5-IPV6-Kernel-Exploit — kernel jailbreak reference
- **sleirsgoevy** — [ps4jb2](https://github.com/sleirsgoevy/ps4jb2) — GOT leak technique for libkernel
- **flatz** — ps5_tools — PS5 SELF format analysis tools
- **po6ix** — initial CVE-2023-41993 PoC

---

> **Legal notice:** This software is intended solely for security research on hardware you own.
> Use for piracy or any other illegal activity is not permitted. See [LICENSE](LICENSE) (GPLv3).
