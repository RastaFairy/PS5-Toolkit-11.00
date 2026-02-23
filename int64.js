/**
 * int64.js — Aritmética de enteros de 64 bits para el exploit WebKit PS5
 *
 * JS usa doubles IEEE-754 de 64 bits, por lo que no puede representar enteros
 * arbitrarios de 64 bits con precisión. Esta clase los divide en dos palabras
 * de 32 bits (hi / lo) y soporta las operaciones que necesitamos en el exploit.
 */

"use strict";

class Int64 {
    /**
     * @param {number|string} lo  Palabra baja (32 bits) o entero completo ≤ 2^53
     * @param {number}        hi  Palabra alta (32 bits), opcional
     */
    constructor(lo, hi) {
        if (hi === undefined) {
            // Construcción desde un número JS nativo (hasta 2^53 es exacto)
            this.lo = lo >>> 0;
            this.hi = Math.floor(lo / 0x100000000) >>> 0;
        } else {
            this.lo = lo >>> 0;
            this.hi = hi >>> 0;
        }
    }

    /** Crea un Int64 desde un ArrayBuffer (little-endian) */
    static fromBuffer(buf, offset = 0) {
        const view = new DataView(buf);
        const lo   = view.getUint32(offset,     true);
        const hi   = view.getUint32(offset + 4, true);
        return new Int64(lo, hi);
    }

    /** Escribe el valor en un ArrayBuffer en la posición dada (little-endian) */
    toBuffer(buf, offset = 0) {
        const view = new DataView(buf);
        view.setUint32(offset,     this.lo, true);
        view.setUint32(offset + 4, this.hi, true);
    }

    /** Suma de 64 bits (sin signo, desbordamiento ignorado) */
    add(other) {
        const lo = (this.lo + other.lo) >>> 0;
        const carry = (this.lo + other.lo) > 0xffffffff ? 1 : 0;
        const hi = (this.hi + other.hi + carry) >>> 0;
        return new Int64(lo, hi);
    }

    /** Suma de un número pequeño (< 2^32) */
    add32(n) {
        return this.add(new Int64(n >>> 0, 0));
    }

    /** Resta de 64 bits */
    sub(other) {
        let lo = (this.lo - other.lo) >>> 0;
        let borrow = this.lo < other.lo ? 1 : 0;
        let hi = (this.hi - other.hi - borrow) >>> 0;
        return new Int64(lo, hi);
    }

    /** AND bit a bit */
    and(other) {
        return new Int64(this.lo & other.lo, this.hi & other.hi);
    }

    /** OR bit a bit */
    or(other) {
        return new Int64(this.lo | other.lo, this.hi | other.hi);
    }

    /** XOR bit a bit */
    xor(other) {
        return new Int64(this.lo ^ other.lo, this.hi ^ other.hi);
    }

    /** Desplazamiento lógico a la derecha (n bits, 0-63) */
    shr(n) {
        if (n === 0) return new Int64(this.lo, this.hi);
        if (n >= 32) return new Int64(this.hi >>> (n - 32), 0);
        const lo = ((this.lo >>> n) | (this.hi << (32 - n))) >>> 0;
        const hi = this.hi >>> n;
        return new Int64(lo, hi);
    }

    /** Desplazamiento lógico a la izquierda (n bits, 0-63) */
    shl(n) {
        if (n === 0) return new Int64(this.lo, this.hi);
        if (n >= 32) return new Int64(0, this.lo << (n - 32));
        const hi = ((this.hi << n) | (this.lo >>> (32 - n))) >>> 0;
        const lo = (this.lo << n) >>> 0;
        return new Int64(lo, hi);
    }

    /** Compara con otro Int64. Devuelve -1, 0 o 1 */
    compare(other) {
        if (this.hi !== other.hi) return this.hi < other.hi ? -1 : 1;
        if (this.lo !== other.lo) return this.lo < other.lo ? -1 : 1;
        return 0;
    }

    equals(other) { return this.compare(other) === 0; }
    lt(other)     { return this.compare(other) < 0;   }
    gt(other)     { return this.compare(other) > 0;   }

    /** Representación hexadecimal con prefijo 0x */
    toString() {
        const hi = this.hi.toString(16).padStart(8, '0');
        const lo = this.lo.toString(16).padStart(8, '0');
        return `0x${hi}${lo}`;
    }

    /** Convierte a número JS nativo (preciso sólo si < 2^53) */
    toNumber() {
        return this.hi * 0x100000000 + this.lo;
    }

    /** Construye desde string hex "0x..." */
    static fromHex(hex) {
        hex = hex.replace(/^0x/, '');
        while (hex.length < 16) hex = '0' + hex;
        const hi = parseInt(hex.slice(0, 8), 16);
        const lo = parseInt(hex.slice(8),    16);
        return new Int64(lo, hi);
    }

    /** Utilidad: convierte un float IEEE-754 de 64 bits a Int64 */
    static fromDouble(d) {
        const buf = new ArrayBuffer(8);
        new Float64Array(buf)[0] = d;
        return Int64.fromBuffer(buf);
    }

    /** Convierte un Int64 a float IEEE-754 de 64 bits */
    toDouble() {
        const buf = new ArrayBuffer(8);
        this.toBuffer(buf);
        return new Float64Array(buf)[0];
    }
}
