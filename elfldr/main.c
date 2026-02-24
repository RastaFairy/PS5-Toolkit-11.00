/**
 * main.c — Persistent ELF Loader TCP Listener
 *
 * This program is injected into SceRedisServer via ptrace (see pt.c).
 * It runs as a persistent TCP listener on port 9021, accepts ELF/BIN/SELF
 * files from the host PC, and executes them in a forked child process.
 *
 * Build with ps5-payload-sdk:
 *   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
 *   make -C elfldr/
 *
 * Architecture: FreeBSD AMD64 (Orbis OS)
 * Compile target: PS5 payload ELF (position-independent, no standard libc)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "elfldr.h"

/* ─── Configuration ──────────────────────────────────────────────────────── */

#define LISTEN_PORT      9021
#define LISTEN_BACKLOG   4
#define RECV_BUF_SIZE    (8 * 1024 * 1024)   /* 8 MB max payload */
#define LOG_UDP_PORT     9998

/* ─── UDP log helper ─────────────────────────────────────────────────────── */

static int g_log_sock = -1;
static struct sockaddr_in g_log_addr;

/**
 * Initialise the UDP log socket.
 * Log messages are broadcast to 255.255.255.255:9998 and received by
 * tools/listen_log.py on the host PC.
 */
static void log_init(void) {
    g_log_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_log_sock < 0) return;

    int broadcast = 1;
    setsockopt(g_log_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    memset(&g_log_addr, 0, sizeof(g_log_addr));
    g_log_addr.sin_family      = AF_INET;
    g_log_addr.sin_port        = htons(LOG_UDP_PORT);
    g_log_addr.sin_addr.s_addr = INADDR_BROADCAST;
}

/**
 * Send a log message via UDP broadcast.
 * @param msg  Null-terminated string.
 */
static void log_send(const char *msg) {
    if (g_log_sock < 0) return;
    size_t len = strlen(msg);
    sendto(g_log_sock, msg, len, 0,
           (struct sockaddr *)&g_log_addr, sizeof(g_log_addr));
}

/* ─── Receive helpers ────────────────────────────────────────────────────── */

/**
 * Receive exactly `len` bytes from `fd` into `buf`.
 * Returns 0 on success, -1 on error or EOF.
 */
static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n <= 0) return -1;
        received += (size_t)n;
    }
    return 0;
}

/**
 * Receive a variable-length payload from `fd`.
 * Reads until the sender closes the connection.
 *
 * Returns a malloc'd buffer (caller must free) and sets *out_len.
 * Returns NULL on error.
 */
static uint8_t *recv_payload(int fd, size_t *out_len) {
    uint8_t *buf = (uint8_t *)mmap_alloc(RECV_BUF_SIZE);
    if (!buf) {
        log_send("[elfldr] [error] Failed to allocate receive buffer");
        return NULL;
    }

    size_t total = 0;
    ssize_t n;

    while (total < RECV_BUF_SIZE) {
        n = recv(fd, buf + total, RECV_BUF_SIZE - total, 0);
        if (n == 0) break;   /* sender closed connection — payload complete */
        if (n < 0) {
            log_send("[elfldr] [error] recv() failed during payload receive");
            mmap_free(buf, RECV_BUF_SIZE);
            return NULL;
        }
        total += (size_t)n;
    }

    if (total == 0) {
        log_send("[elfldr] [warn] Received empty payload");
        mmap_free(buf, RECV_BUF_SIZE);
        return NULL;
    }

    *out_len = total;
    return buf;
}

/* ─── Connection handler ─────────────────────────────────────────────────── */

/**
 * Handle a single incoming connection:
 *   1. Receive the payload
 *   2. Detect format (ELF64 / SELF / RAW)
 *   3. Fork a child process
 *   4. In the child: load and execute the payload
 *   5. In the parent: wait for the child and log result
 *
 * @param conn_fd  Accepted client socket fd.
 * @param peer     Client address (for logging).
 */
static void handle_connection(int conn_fd, struct sockaddr_in *peer) {
    char peer_str[32];
    snprintf(peer_str, sizeof(peer_str), "%s:%d",
             inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));

    log_send("[elfldr] Connection from ");
    log_send(peer_str);

    size_t   payload_len = 0;
    uint8_t *payload     = recv_payload(conn_fd, &payload_len);
    close(conn_fd);

    if (!payload) return;

    /* Detect format */
    elfldr_fmt_t fmt = elfldr_detect_format(payload, payload_len);
    const char *fmt_name =
        fmt == ELFLDR_FMT_ELF64 ? "ELF64" :
        fmt == ELFLDR_FMT_SELF  ? "SELF"  : "RAW";

    log_send("[elfldr] Payload received, format: ");
    log_send(fmt_name);

    /* Fork and execute */
    pid_t pid = fork();

    if (pid < 0) {
        log_send("[elfldr] [error] fork() failed");
        mmap_free(payload, RECV_BUF_SIZE);
        return;
    }

    if (pid == 0) {
        /* ── Child process ── */
        int rc = elfldr_exec(payload, payload_len, fmt);
        /* elfldr_exec should not return on success */
        log_send("[elfldr] [error] elfldr_exec() returned unexpectedly");
        _exit(rc);
    }

    /* ── Parent process ── */
    mmap_free(payload, RECV_BUF_SIZE);

    int status = 0;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        log_send("[elfldr] Child exited normally");
    } else if (WIFSIGNALED(status)) {
        log_send("[elfldr] [warn] Child killed by signal");
    }
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

/**
 * Main entry point — called after ptrace injection into SceRedisServer.
 *
 * Sets up the TCP listener and enters an accept() loop.
 * This function is designed to never return.
 */
void elfldr_main(void) {
    log_init();
    log_send("[elfldr] Loader starting on port 9021...");

    /* Create TCP listening socket */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        log_send("[elfldr] [fatal] socket() failed");
        return;
    }

    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_send("[elfldr] [fatal] bind() failed");
        close(srv);
        return;
    }

    if (listen(srv, LISTEN_BACKLOG) < 0) {
        log_send("[elfldr] [fatal] listen() failed");
        close(srv);
        return;
    }

    log_send("[elfldr] Listening on port 9021 — ready for payloads");

    /* Accept loop */
    while (1) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        int conn = accept(srv, (struct sockaddr *)&peer, &peer_len);
        if (conn < 0) {
            if (errno == EINTR) continue;
            log_send("[elfldr] [warn] accept() error, continuing...");
            continue;
        }

        handle_connection(conn, &peer);
    }

    /* Never reached */
    close(srv);
}
