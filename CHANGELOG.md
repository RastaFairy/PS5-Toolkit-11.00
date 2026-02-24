# Changelog — PS5 Toolkit 11.00

## [Unreleased]

### Pending

- **Verify offsets against real FW 11.00 binaries**
  Run `python3 tools/gen_offsets.py --libkernel libkernel.elf --webkit WebKit.elf --kernel mini-syscore.elf`.
  Current values are estimates derived from static analysis and earlier firmware versions.
  Fields marked `// ⚠ VERIFY` in `offsets_1100.js`.

- **`prison0` offset in `kernel.js`**
  The `kernel.kbase_placeholder` field in `offsets_1100.js` is a placeholder.
  `analyze_kernel.py` extracts the real offset automatically once the kernel `.elf` is provided.

- **Empirical verification of `worker_ret_offset`**
  The value `0x7FB88` is an estimate based on earlier firmware versions.
  It must be verified on hardware once the bug is triggering.
  See `docs/offsets_guide.md → Empirical Worker verification`.

- **Unit tests for `tools/send_payload.py` and `tools/server.py`**
  Pending pytest suite: payload type detection by magic bytes, ELF64 validation,
  network error handling and timeout coverage.

---

## [0.3.0] — 2025-02 (session 3)

### Added

#### `exploit/js/webkit_bug.js` — new module, 827 lines

- **`triggerWebKitBug()`** fully implemented based on CVE-2023-41993
  (DFG JIT type confusion in JavaScriptCore)
  - *Phase 1 — Heap spray:* 0x800 `ArrayBuffer`s of 64 bytes colour the JSC allocator
    heap to predict the confused object's placement
  - *Phase 2 — Confusion objects:* `confused/container` pair with
    `STRUCTURE_TRANSITION_COUNT = 3` controlled structure transitions that activate
    the vulnerable `clobberize()` path in the DFG compiler
  - *Phase 3 — JIT warmup:* 100 iterations of `jitCompiledRead/Write` embed the
    "double" type speculation in compiled DFG code
  - *Phase 4 — Trigger and verification:* breaks the type invariant; up to 3 automatic
    retries with address range validation; verifies `leakobj` and `fakeobj` with a
    round-trip test before returning
  - Tuning constants documented and justified: `JIT_WARMUP_ITERS`, `SPRAY_COUNT`,
    `SPRAY_AB_SIZE`, `STRUCTURE_TRANSITION_COUNT`, `FAKE_AB_SIZE`
  - `jitCompiledRead` and `jitCompiledWrite` defined in global scope (not as closures)
    to ensure correct DFG compilation
  - `leakobj(obj)` and `fakeobj(addr)` with inline explanation of JSC NaN-boxing and
    the non-JIT read path used for `fakeobj`
  - `corrupt()` as a bootstrapping utility for direct offset writes
  - `detectJSEngine()` — confirms we are running in JavaScriptCore before proceeding
  - `patchOffset(path, value)` — update any `OFFSETS` entry at runtime from the
    PS5 WebInspector console without reloading the page

- **`leakLibKernelBase(p)`** implemented in `webkit_bug.js`
  - `addrof(new RegExp('a'))` → reads internal `JSRegExp*` at inline slot +0x10 →
    reads C++ vtable → subtracts `vtable_jsregexp_offset` → `webkit_base`
  - Reads `GOT[pthread_create]` at `webkit_base + got_pthread_create` →
    subtracts libkernel symbol offset → `libkBase`
  - Page-alignment check on the final result; actionable error messages at each step

#### `exploit/js/offsets_1100.js` — new fields

- `webkit` section extended with: `vtable_jsregexp_offset`, `regexp_internal_offset`,
  `got_pthread_create`, `got_mmap`, `got_write`
- New `libkernel_syms` section with individual function offsets for the GOT read:
  `pthread_create`, `pthread_self`, `mmap`, `write`
- All new fields annotated with `// ⚠ VERIFY` and instructions on how to obtain them

#### `exploit/index.html`

- Added `webkit_bug.js` script tag in the correct load order
- Removed `triggerWebKitBug()` and `leakLibKernelBase()` stubs that threw `not implemented`

#### `tools/` — automated firmware binary analysis suite (5 new scripts)

- **`self2elf.py`** — converts PS5 SELF/SPRX to plain ELF, no pip dependencies
  - Single-file mode, directory batch mode (`--dir`/`--out`), and inspection mode (`--check`)
  - Detects encrypted vs decrypted SELF; transparently passes files that are already ELF
  - Validates ELF64 class and x86-64 architecture on output

- **`analyze_libkernel.py`** — extracts offsets from `libkernel.elf` in 4 passes
  - ROP gadgets (pop rdi/rsi/rdx/rcx/r8/r9/rax/rsp; ret, syscall; ret, xchg rax,rsp)
    via full disassembly with objdump and 1–4 instruction window search
  - 20 function symbols via nm; thread_list via known pthread global hints
  - `pthread_t` field offsets by disassembly analysis of `pthread_attr_getstack`
    with heuristic range fallback to known FreeBSD 11 values
  - GOT entries for libkBase leak; generates JS fragment ready to paste into `offsets_1100.js`

- **`analyze_webkit.py`** — extracts offsets from `WebKit.elf` in 3 passes
  - Reads the dynamic relocation table (`readelf -r`) to enumerate GOT entries
  - Cross-references with `libkernel.elf` (optional) to compute the final symbol offset
  - Automatically selects the best candidate by preference order
  - Searches for Worker-related strings and `0x80000` references in the disassembly

- **`analyze_kernel.py`** — extracts offsets from the kernel ELF in 3 passes
  - Symbols: `allproc`, `prison0`, `kern_securelevel`, `rootvnode`, `nproc`
  - `struct proc` offsets by disassembly analysis of `pfind()` with range heuristics
  - `struct ucred` offsets with FreeBSD 11 values as documented fallback

- **`gen_offsets.py`** — master orchestrator
  - Invokes all three analysers; auto-converts SPRX→ELF if `.sprx` paths are provided
  - Generates complete `offsets_1100.js` with per-section confidence indicators
    (HIGH / MEDIUM / LOW), Orbis OS syscall constants, and an `OFFSETS_1100` export object
  - Flags: `--libkernel`, `--webkit`, `--kernel`, `--out`, `--tmp`, `--verbose`,
    `--libkernel-sprx`, `--webkit-sprx`

- **`tools/ANALYSIS_README.md`** — full usage guide for the analysis tools

---

## [0.2.0] — 2025-02 (session 2)

### Added

#### Visual documentation in Spanish

- **`ps5-toolkit-descripcion.html`** — interactive Spanish visual guide
  - Dark cyberpunk aesthetic (Space Mono, Syne, IBM Plex Mono); PS5 blue/cyan palette
  - 9 sections: hero, project overview, security mitigations table
    (SMEP/SMAP/XOM/CFI/Hypervisor), 7-step exploit chain diagram, PC↔PS5 architecture,
    descriptions of 12 modules, file tree, parallel user/system steps, project checklist

- **`ps5-toolkit-plan-tutorial.html`** — action plan and technical tutorial
  - 4 tasks prioritised by impact: BLOCKER / CRITICAL / MEDIUM / LOW
  - 3-phase plan with time estimates per phase
  - Tutorial T1–T5 with exact commands, commented code snippets, and source references

#### Project files completed

- **`LICENSE`** — full GPLv3 text (all 17 sections)
- **`CONTRIBUTING.md`** — contribution guide with priority areas table,
  commit conventions (`feat/fix/docs/offset/refactor`), code standards for JS/C/Python,
  and security guidelines for contributors
- **`setup.sh`** — multi-OS automated installer
  - OS detection: Debian/Ubuntu, macOS, Arch Linux
  - Dependency checks: Python ≥3.8, git, netcat, clang/make (with `--sdk`)
  - Auto-detects local IP and patches `HOST_IP` in `loader.js` and `hello.c`
  - `--sdk` flag: clones `ps5-payload-dev/sdk` to `/opt/ps5-payload-sdk` and builds
  - Coloured output with ASCII art banner
- **`exploit/js/rop_worker.js`** — victim Web Worker
  - `onmessage` handler with `warmup` and `trigger` logic
  - Overwritable return address for the stack pivot
  - Load confirmation messages
- **`.github/ISSUE_TEMPLATE/bug_report.md`** — bug report template with
  firmware/OS fields, per-phase checkboxes, and log sections
- **`.github/ISSUE_TEMPLATE/offsets.md`** — offsets contribution template
  with `libkernel`/`WebKit`/`kernel` offset tables and verification method fields

---

## [0.1.0] — 2025-02 (session 1)

### Added

Full project scaffold — 30 files.

#### `exploit/` — WebKit exploit chain

- **`exploit/index.html`** — 5-phase orchestrator UI with progress bar,
  colour-coded real-time logs, and retry button. Loads all JS modules in order.

- **`exploit/js/int64.js`** — 64-bit integer arithmetic for JavaScript
  - `Int64` class: constructors by `(lo, hi)`, `fromDouble()`, `toDouble()`
  - `add32()`, `sub()`, `add()` with correct carry propagation
  - Comparison, `.hi` / `.lo` accessors, `.toString()` in hex

- **`exploit/js/offsets_1100.js`** — FW 11.00 offset table
  - Sections: `libkernel` (syscall stubs, ROP gadgets, pthread),
    `webkit` (worker offsets, gadgets), `kernel` (proc/ucred/prison structures)

- **`exploit/js/primitives.js`** — `Primitives` class
  - `addrof(obj)` → `Int64`; `read8/write8/read4/write4`; `readBytes/writeBytes/readCString`
  - `_setVictimPointer(addr)` — core: overwrites the `vector` field (+0x10)
    of the victim `Float64Array` to point at any address

- **`exploit/js/rop.js`** — ROPChain builder + Worker stack pivot
  - `ROPChain` class with `push()`, `pushAddr()`, `build()`, and gadget resolution
  - `createROPWorker()` — creates the Worker and waits for its load confirmation
  - `findWorkerStack(p, libkBase)` — walks `thread_list`, filters by `stack_size == 0x80000`
  - `executeROPChain()` — overwrites `worker_ret_offset` and sends the trigger message

- **`exploit/js/kernel.js`** — `KernelExploit` class
  - `leakKbase()` — leaks `kbase` via `umtx_op` syscall
  - `findCurrentProcess(allproc)` — walks `allproc` by PID
  - `escalatePrivileges(proc)` — patches `p_ucred`: all UIDs to 0
  - `escapeJail(ucred)` — sets `cr_prison = &prison0`

- **`exploit/js/loader.js`** — `PayloadLoader` class
  - `downloadELF(url)` → downloads `elfldr.elf` from the HTTP server
  - `injectIntoRedis(elfData)` → injects the loader into `SceRedisServer` via ptrace
  - `waitForLoader()` → polls TCP :9021 with timeout

#### `elfldr/` — native ELF loader in C

- **`elfldr.c`** — ELF64 parser: PT_LOAD segments with mmap/mprotect, relocations
  `R_X86_64_RELATIVE/GLOB_DAT/JUMP_SLOT/64`, calls to `DT_INIT`/`DT_INIT_ARRAY`/entry
- **`main.c`** — TCP :9021 server: payload reception, type detection by magic bytes,
  UDP :9998 log broadcast
- **`pt.c`** — ptrace bootstrap: attach, shellcode injection, find `SceRedisServer`,
  execute, detach
- **`elfldr.h`** / **`pt.h`** / **`Makefile`**

#### `payload/example/`

- **`hello.c`** — sends "Hello from PS5!" over UDP and exits cleanly
- **`Makefile`** — builds with ps5-payload-sdk

#### `host/` and `tools/`

- **`host/server.py`** — HTTP server with COOP/COEP/CORS headers for SharedArrayBuffer
- **`tools/send_payload.py`** — TCP client for payload delivery: type detection, progress bar
- **`tools/listen_log.py`** — UDP log receiver with colours and timestamps

#### `docs/`

- **`docs/architecture.md`** — in-depth technical analysis of the full chain
- **`docs/offsets_guide.md`** — step-by-step guide for finding offsets with Ghidra and ROPgadget

#### Repository configuration

- **`README.md`** — full project documentation
- **`.gitignore`** — excludes firmware dumps, `.elf`, `.bin`, `__pycache__`, build artefacts
- **`payloads/.gitkeep`** — directory for user-compiled payloads

---

## Completeness Summary

| Component | v0.1.0 | v0.2.0 | v0.3.0 |
|---|:---:|:---:|:---:|
| `triggerWebKitBug()` | ✗ stub | ✗ stub | ✅ CVE-2023-41993 |
| `leakLibKernelBase()` | ✗ stub | ✗ stub | ✅ GOT + vtable leak |
| `primitives.js` | ✅ | ✅ | ✅ |
| `rop.js` | ✅ | ✅ | ✅ |
| `kernel.js` | ✅ | ✅ | ✅ |
| `loader.js` + `elfldr/` | ✅ | ✅ | ✅ |
| `offsets_1100.js` | ⚠ partial | ⚠ partial | ⚠ verify |
| Analysis tools | 2 scripts | 2 scripts | 7 scripts |
| Spanish documentation | — | ✅ | ✅ |
| Installer | — | ✅ | ✅ |
| GitHub templates | — | ✅ | ✅ |
