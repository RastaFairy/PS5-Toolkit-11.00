# Guide for Non-Developers / Guía para No Desarrolladores

---

# ENGLISH

## What is this project?

This is a **research tool** for security investigators who want to study how the PlayStation 5
browser handles memory. Think of it like a mechanic's manual for a car — it describes every
part of the engine in detail, but two critical pages are still blank (marked TODO).

Without those two blank pages, nothing actually happens on the PS5.

---

## Key concepts, explained simply

### What is a "WebKit exploit"?
Every PS5 has a built-in web browser powered by an engine called **WebKit** and a JavaScript
interpreter called **JavaScriptCore (JSC)**. Security researchers look for bugs in this
interpreter — places where it gets confused about what type of data it's handling — which can
then be used to do things the console wasn't designed to allow.

### What is JIT, and why does it matter that PS5 doesn't have it?
JIT (Just-In-Time compilation) is a speed technique where JavaScript code gets converted into
fast machine instructions while it runs. Many exploits on other platforms target the JIT
compiler because it handles memory in complex ways that are easy to get wrong.

**The PS5 browser has JIT disabled.** This means:
- Any exploit that says "we attack the JIT compiler" is wrong for PS5
- PS5 is actually *harder* to exploit via JavaScript because of this
- This project correctly uses ROP (see below) instead

### What is ROP?
**Return-Oriented Programming** is a technique where, instead of injecting new code, you
chain together tiny snippets of code that already exist in the console's memory. Imagine
building sentences entirely from words cut out of existing books — you can't write new words,
only rearrange existing ones. This is the only way to execute custom code on PS5 because
its browser blocks new code injection.

### What is SharedArrayBuffer and why is it disabled?
SharedArrayBuffer is a JavaScript feature that lets different worker threads share the same
memory simultaneously. It's powerful for performance but also very useful for timing attacks
in exploits. **The PS5 browser has it disabled**, which is why this project uses a simpler
memory technique instead.

### What are "primitives"?
In security research, a "primitive" is a basic building block — a reliable way to do one
specific thing, like "read 8 bytes from any memory address" or "write 8 bytes to any address."
Once you have these two primitives, you can do almost anything else. The hardest part of this
project (the TODO section) is building those two primitives from the initial bug.

---

## Why are two parts blank?

The two TODO functions (`triggerWebKitBug` and `leakLibKernelBase`) require analyzing the
actual binary files inside a PS5 running firmware 11.00. This means:
- Dumping the console's memory
- Using reverse engineering tools (like Ghidra) to find specific memory addresses
- Identifying exactly which version of a known bug is present

This project documents everything *around* that analysis but leaves that specific work
for researchers with access to the hardware and the appropriate legal context.

---

## Is this legal to use?

This depends entirely on your jurisdiction and situation. Generally:
- **Studying the code** for educational purposes: legal in most places
- **Running it on a PS5 you own** for research: legal in many jurisdictions
- **Using it to play pirated games** or bypass DRM: violates laws in most countries
  and Sony's terms of service

When in doubt, consult a lawyer familiar with computer security law in your country.

---

---

# ESPAÑOL

## ¿Qué es este proyecto?

Es una **herramienta de investigación** para investigadores de seguridad que quieren estudiar
cómo el navegador de PlayStation 5 maneja la memoria. Imagínalo como el manual del mecánico
de un coche — describe cada pieza del motor con detalle, pero dos páginas críticas todavía
están en blanco (marcadas como TODO).

Sin esas dos páginas en blanco, no ocurre nada real en la PS5.

---

## Conceptos clave, explicados de forma simple

### ¿Qué es un "exploit de WebKit"?
Toda PS5 tiene un navegador web integrado impulsado por un motor llamado **WebKit** y un
intérprete de JavaScript llamado **JavaScriptCore (JSC)**. Los investigadores de seguridad
buscan fallos en este intérprete — lugares donde se confunde con el tipo de datos que está
manejando — que luego pueden usarse para hacer cosas que la consola no fue diseñada para permitir.

### ¿Qué es JIT y por qué importa que la PS5 no lo tenga?
JIT (compilación Just-In-Time) es una técnica de velocidad donde el código JavaScript se
convierte en instrucciones rápidas de máquina mientras se ejecuta. Muchos exploits en otras
plataformas atacan el compilador JIT porque maneja la memoria de formas complejas que son
fáciles de implementar mal.

**El navegador de PS5 tiene el JIT desactivado.** Esto significa:
- Cualquier exploit que diga "atacamos el compilador JIT" es incorrecto para PS5
- La PS5 es en realidad *más difícil* de explotar vía JavaScript por esto
- Este proyecto usa correctamente ROP (ver más abajo) en su lugar

### ¿Qué es ROP?
**Return-Oriented Programming** (Programación Orientada a Retornos) es una técnica donde,
en lugar de inyectar código nuevo, encadenas pequeños fragmentos de código que ya existen
en la memoria de la consola. Imagina construir frases usando únicamente palabras recortadas
de libros ya existentes — no puedes escribir palabras nuevas, solo reorganizar las existentes.
Esta es la única forma de ejecutar código personalizado en PS5 porque su navegador bloquea
la inyección de código nuevo.

### ¿Qué es SharedArrayBuffer y por qué está desactivado?
SharedArrayBuffer es una función de JavaScript que permite que distintos hilos de trabajo
compartan la misma memoria simultáneamente. Es muy útil para rendimiento pero también muy
útil para ataques de temporización en exploits. **El navegador de PS5 lo tiene desactivado**,
por eso este proyecto usa una técnica de memoria más simple.

### ¿Qué son las "primitivas"?
En investigación de seguridad, una "primitiva" es un bloque de construcción básico — una
forma fiable de hacer una cosa específica, como "leer 8 bytes de cualquier dirección de
memoria" o "escribir 8 bytes en cualquier dirección". Una vez que tienes esas dos primitivas,
puedes hacer casi cualquier otra cosa. La parte más difícil de este proyecto (la sección TODO)
es construir esas dos primitivas a partir del fallo inicial.

---

## ¿Por qué están en blanco dos partes?

Las dos funciones TODO (`triggerWebKitBug` y `leakLibKernelBase`) requieren analizar los
ficheros binarios reales dentro de una PS5 con el firmware 11.00. Esto significa:
- Volcar la memoria de la consola
- Usar herramientas de ingeniería inversa (como Ghidra) para encontrar direcciones de memoria específicas
- Identificar exactamente qué versión de un fallo conocido está presente

Este proyecto documenta todo lo que *rodea* ese análisis pero deja ese trabajo específico
para investigadores con acceso al hardware y el contexto legal apropiado.

---

## ¿Es legal usar esto?

Depende completamente de tu jurisdicción y situación. En general:
- **Estudiar el código** con fines educativos: legal en la mayoría de sitios
- **Ejecutarlo en una PS5 que tú posees** para investigación: legal en muchas jurisdicciones
- **Usarlo para jugar juegos pirateados** o saltarse el DRM: viola leyes en la mayoría de países
  y los términos de servicio de Sony

En caso de duda, consulta a un abogado familiarizado con la ley de seguridad informática en tu país.

---

*Este documento no constituye asesoramiento legal / This document does not constitute legal advice*
