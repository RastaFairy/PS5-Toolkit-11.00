/**
 * payload/example/hello.c — Payload de ejemplo mínimo para PS5
 *
 * Este payload:
 *   1. Abre un socket TCP hacia el PC (puerto 9997)
 *   2. Envía un mensaje de saludo con información del sistema
 *   3. Cierra la conexión y termina
 *
 * Es el "Hello World" de los payloads PS5.
 * Compilar con ps5-payload-sdk: make
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Configuración ─────────────────────────────────────────────────────── */

/* IP del PC que ejecuta el listener (ajustar antes de compilar) */
#define PC_IP    "192.168.1.100"
#define PC_PORT  9997

/* ── Punto de entrada ──────────────────────────────────────────────────── */

int _start(void) {
    /* Abrir socket TCP hacia el PC */
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return 1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(PC_PORT),
    };
    inet_pton(AF_INET, PC_IP, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 2;
    }

    /* Enviar mensaje */
    const char *msg =
        "=== PS5 Toolkit 11.xx ===\n"
        "Hola desde la PS5!\n"
        "El payload 'hello' se ejecutó correctamente.\n"
        "ELF loader activo en puerto 9021.\n"
        "========================\n";

    send(fd, msg, strlen(msg), 0);
    close(fd);

    return 0;
}
