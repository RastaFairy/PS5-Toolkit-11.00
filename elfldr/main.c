/**
 * main.c — ELF Loader para PS5 FW 11.xx
 *
 * Este loader se inyecta en SceRedisServer via ptrace para persistir
 * incluso durante el rest mode y los cambios de juego.
 *
 * Una vez activo, escucha en el puerto 9021 (TCP) y acepta payloads
 * en formato ELF, RAW binario, o SELF.
 *
 * Compilar con ps5-payload-sdk:
 *   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
 *   make
 *
 * Arquitectura basada en:
 *   - john-tornblom/ps5-payload-elfldr (técnica ptrace + SceRedisServer)
 *   - ps5-payload-dev/elfldr (versión actualizada)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

#include "elfldr.h"
#include "pt.h"

/* ── Configuración ─────────────────────────────────────────────────────── */

#define LISTEN_PORT      9021
#define LISTEN_BACKLOG   4
#define MAX_PAYLOAD_SIZE (64 * 1024 * 1024)   /* 64 MiB máximo por payload  */
#define LOG_UDP_PORT     9998                  /* Receptor de logs en el PC   */

/* Nombre del proceso destino para el bootstrap vía ptrace */
#define TARGET_PROCESS   "SceRedisServer"

/* ── Tipos internos ────────────────────────────────────────────────────── */

typedef struct {
    int   fd;             /* Socket del cliente conectado */
    pid_t child_pid;      /* PID del proceso hijo que ejecuta el payload */
} PayloadSession;

/* ── Prototipos ────────────────────────────────────────────────────────── */

static int  setup_listener(uint16_t port);
static int  receive_payload(int client_fd, uint8_t **buf_out, size_t *len_out);
static int  dispatch_payload(int client_fd, uint8_t *buf, size_t len);
static void reap_children(void);
static void log_message(const char *fmt, ...);

/* ── Punto de entrada ──────────────────────────────────────────────────── */

int _start(void) {
    log_message("ps5-elfldr arrancando en puerto %d", LISTEN_PORT);

    /* Primero hacemos el bootstrap en SceRedisServer para persistir */
    if (pt_bootstrap(TARGET_PROCESS) != 0) {
        log_message("ADVERTENCIA: no se pudo hacer bootstrap en %s; "
                    "el loader se ejecutará en el proceso actual", TARGET_PROCESS);
    } else {
        log_message("Bootstrap en %s completado", TARGET_PROCESS);
    }

    int srv_fd = setup_listener(LISTEN_PORT);
    if (srv_fd < 0) {
        log_message("ERROR: no se pudo crear el socket servidor: %d", errno);
        return 1;
    }

    log_message("Escuchando en 0.0.0.0:%d ...", LISTEN_PORT);

    /* Bucle principal: acepta conexiones indefinidamente */
    for (;;) {
        /* Limpiar procesos hijo zombie */
        reap_children();

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(srv_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) continue;
            log_message("accept() falló: %d", errno);
            continue;
        }

        log_message("Conexión desde %08x:%d",
                    client_addr.sin_addr.s_addr,
                    ntohs(client_addr.sin_port));

        uint8_t *payload_buf = NULL;
        size_t   payload_len = 0;

        if (receive_payload(client_fd, &payload_buf, &payload_len) == 0) {
            dispatch_payload(client_fd, payload_buf, payload_len);
        } else {
            log_message("Error recibiendo payload");
        }

        /* payload_buf se libera dentro del proceso hijo si fork() tuvo éxito;
         * en el padre lo liberamos aquí si dispatch no hizo fork */
        if (payload_buf) {
            munmap(payload_buf, payload_len);
        }

        close(client_fd);
    }

    /* Nunca se alcanza */
    close(srv_fd);
    return 0;
}

/* ── Configuración del socket de escucha ──────────────────────────────── */

static int setup_listener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;

    /* Permitir reutilizar el puerto inmediatamente */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, LISTEN_BACKLOG) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* ── Recepción del payload ─────────────────────────────────────────────── */

/**
 * Lee el payload completo del socket.
 * Protocolo: los primeros 4 bytes son el tamaño en little-endian,
 * seguido de los datos del payload. Si el cliente no envía el header
 * de tamaño, leemos hasta que cierre la conexión (modo raw).
 *
 * Para compatibilidad con netcat simple, soportamos el modo raw:
 * si los primeros bytes son el magic ELF (\x7fELF), leemos hasta EOF.
 */
static int receive_payload(int client_fd, uint8_t **buf_out, size_t *len_out) {
    /* Leer los primeros 4 bytes para determinar el modo */
    uint8_t header[4];
    ssize_t n = recv(client_fd, header, sizeof(header), MSG_PEEK | MSG_WAITALL);
    if (n < 4) return -1;

    size_t expected_size;

    /* Detectar modo por magic bytes */
    if (header[0] == 0x7F && header[1] == 'E' &&
        header[2] == 'L'  && header[3] == 'F') {
        /* Modo raw ELF: leer hasta EOF, máximo MAX_PAYLOAD_SIZE */
        expected_size = MAX_PAYLOAD_SIZE;
    } else if (header[0] == 0x00 && header[1] == 'P' &&
               header[2] == 'S'  && header[3] == 'F') {
        /* Modo SELF (.self / .sprx firmado) */
        expected_size = MAX_PAYLOAD_SIZE;
    } else {
        /* Modo con header de tamaño: leer 4 bytes de size */
        recv(client_fd, header, 4, MSG_WAITALL);
        expected_size = (uint32_t)header[0]
                      | ((uint32_t)header[1] << 8)
                      | ((uint32_t)header[2] << 16)
                      | ((uint32_t)header[3] << 24);
        if (expected_size == 0 || expected_size > MAX_PAYLOAD_SIZE) {
            log_message("Tamaño de payload inválido: %zu", expected_size);
            return -1;
        }
    }

    /* Asignar buffer con mmap para poder ejecutarlo luego */
    uint8_t *buf = mmap(NULL, expected_size,
                        PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) {
        log_message("mmap(%zu) falló: %d", expected_size, errno);
        return -1;
    }

    /* Leer datos */
    size_t total = 0;
    while (total < expected_size) {
        ssize_t received = recv(client_fd, buf + total, expected_size - total, 0);
        if (received <= 0) break;   /* EOF o error */
        total += (size_t)received;
    }

    if (total == 0) {
        munmap(buf, expected_size);
        return -1;
    }

    log_message("Payload recibido: %zu bytes", total);
    *buf_out = buf;
    *len_out = total;
    return 0;
}

/* ── Despacho del payload ──────────────────────────────────────────────── */

/**
 * Determina el tipo de payload y lo ejecuta en un proceso hijo.
 * El proceso hijo hereda el contexto jailbroken del padre.
 */
static int dispatch_payload(int client_fd, uint8_t *buf, size_t len) {
    PayloadType type = elfldr_detect_type(buf, len);

    log_message("Tipo detectado: %s",
                type == PAYLOAD_ELF  ? "ELF"  :
                type == PAYLOAD_SELF ? "SELF" : "RAW");

    pid_t child = fork();
    if (child < 0) {
        log_message("fork() falló: %d", errno);
        return -1;
    }

    if (child == 0) {
        /* ── Proceso hijo ── */

        /* Enviar el fd del cliente al payload para que pueda escribir output */
        /* (los payloads pueden escribir en stdout → client_fd redirigido)   */
        dup2(client_fd, STDOUT_FILENO);
        dup2(client_fd, STDERR_FILENO);

        int ret = elfldr_exec(buf, len, type);
        _exit(ret);
    }

    /* ── Proceso padre ── */
    log_message("Payload lanzado en PID %d", (int)child);
    return 0;
}

/* ── Limpieza de procesos hijo ─────────────────────────────────────────── */

static void reap_children(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            log_message("PID %d terminó con código %d",
                        (int)pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            log_message("PID %d terminado por señal %d",
                        (int)pid, WTERMSIG(status));
        }
    }
}

/* ── Log ────────────────────────────────────────────────────────────────── */

#include <stdarg.h>
#include <stdio.h>

/**
 * Envía un mensaje de log via UDP al PC (puerto 9998).
 * También lo escribe en stderr para depuración local.
 */
static void log_message(const char *fmt, ...) {
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);

    if (n < 0) return;
    buf[n]     = '\n';
    buf[n + 1] = '\0';

    /* Stderr (visible si hay consola) */
    write(STDERR_FILENO, buf, n + 1);

    /* UDP al PC — ignoramos errores */
    static int udp_fd = -1;
    static struct sockaddr_in pc_addr;

    if (udp_fd < 0) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_fd >= 0) {
            memset(&pc_addr, 0, sizeof(pc_addr));
            pc_addr.sin_family      = AF_INET;
            pc_addr.sin_port        = htons(LOG_UDP_PORT);
            /* Broadcast local — ajustar si se conoce la IP del PC */
            pc_addr.sin_addr.s_addr = 0xFFFFFFFF; /* 255.255.255.255 */
        }
    }

    if (udp_fd >= 0) {
        sendto(udp_fd, buf, n + 1, 0,
               (struct sockaddr *)&pc_addr, sizeof(pc_addr));
    }
}
