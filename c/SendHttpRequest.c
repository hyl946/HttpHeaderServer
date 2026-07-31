#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>

#define RECV_BUF_SIZE 8192
#define REQ_BUF_SIZE  16384

/* 解析 http://host[:port][/path] ，返回 0 成功 */
static int parse_url(const char *url, char *host, size_t host_len,
                     int *port, char *path, size_t path_len) {
    const char *p = url;

    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port = 80;
    } else {
        fprintf(stderr, "only http:// is supported: %s\n", url);
        return -1;
    }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hlen;

    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - p);
        *port = atoi(colon + 1);
    } else if (slash) {
        hlen = (size_t)(slash - p);
    } else {
        hlen = strlen(p);
    }

    if (hlen == 0 || hlen >= host_len) {
        fprintf(stderr, "invalid host in url: %s\n", url);
        return -1;
    }
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    if (slash) {
        strncpy(path, slash, path_len - 1);
        path[path_len - 1] = '\0';
    } else {
        strncpy(path, "/", path_len - 1);
        path[path_len - 1] = '\0';
    }
    return 0;
}

/* 确保 headers 以 \r\n 结尾（若非空） */
static void normalize_headers(const char *headers, char *out, size_t out_len) {
    if (!headers || headers[0] == '\0') {
        out[0] = '\0';
        return;
    }
    size_t len = strlen(headers);
    if (len >= out_len - 3) {
        len = out_len - 3;
    }
    memcpy(out, headers, len);
    out[len] = '\0';
    if (len >= 2 && out[len - 2] == '\r' && out[len - 1] == '\n') {
        return;
    }
    if (len >= 1 && out[len - 1] == '\n') {
        /* 单 \n 结尾，补成 \r\n 较麻烦，直接追加一对空行分隔前的 \r\n */
        strcat(out, "\r\n");
        return;
    }
    strcat(out, "\r\n");
}

void send_request(const char *url, const char *method, const char *headers, const char *body) {
    char host[256];
    char path[1024];
    int port = 80;
    char hdr_buf[8192];
    char req[REQ_BUF_SIZE];
    char recv_buf[RECV_BUF_SIZE];
    int sock = -1;
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[16];
    ssize_t n;
    size_t body_len = (body && body[0]) ? strlen(body) : 0;

    printf("send request to %s\n", url);
    printf("headers: %s\n", headers ? headers : "(null)");
    printf("body: %s\n", body ? body : "(null)");
    printf("method: %s\n", method ? method : "(null)");

    if (!url || !method) {
        fprintf(stderr, "url and method are required\n");
        return;
    }

    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0) {
        return;
    }

    normalize_headers(headers, hdr_buf, sizeof(hdr_buf));

    /* 若调用方未提供 Content-Length，且有 body，则补上 */
    if (body_len > 0 && strstr(hdr_buf, "Content-Length:") == NULL
        && strstr(hdr_buf, "content-length:") == NULL) {
        char cl[64];
        snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n", body_len);
        if (strlen(hdr_buf) + strlen(cl) < sizeof(hdr_buf) - 1) {
            strcat(hdr_buf, cl);
        }
    }

    int written = snprintf(req, sizeof(req),
                           "%s %s HTTP/1.1\r\n"
                           "%s"
                           "\r\n"
                           "%s",
                           method, path, hdr_buf, body ? body : "");
    if (written < 0 || (size_t)written >= sizeof(req)) {
        fprintf(stderr, "request too large\n");
        return;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed for %s:%d: %s\n", host, port, strerror(errno));
        return;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        fprintf(stderr, "connect to %s:%d failed: %s\n", host, port, strerror(errno));
        return;
    }

    size_t to_send = (size_t)written;
    size_t sent = 0;
    while (sent < to_send) {
        n = send(sock, req + sent, to_send - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "send failed: %s\n", strerror(errno));
            close(sock);
            return;
        }
        sent += (size_t)n;
    }

    printf("--- response ---\n");
    for (;;) {
        n = recv(sock, recv_buf, sizeof(recv_buf) - 1, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "recv failed: %s\n", strerror(errno));
            break;
        }
        if (n == 0) {
            break;
        }
        recv_buf[n] = '\0';
        fputs(recv_buf, stdout);
    }
    printf("\n--- end ---\n\n");

    close(sock);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    const char *headers =
        "A: A\r\nB: B\r\nHost: test.com\r\nuser-agent: curl/7.64.1\r\n"
        "Accept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\n"
        "C: C\r\nD: D\r\nE: E\r\nF: F\r\nG: G\r\nH: H\r\nI: I\r\nJ: J\r\n"
        "K: K\r\nL: L\r\nM: M\r\nN: N\r\nO: O\r\nP: P\r\nQ: Q\r\nR: R\r\n"
        "S: S\r\nT: T\r\nU: U\r\nV: V\r\nW: W\r\nX: X\r\nY: Y\r\nZ: Z\r\n";
    send_request("http://192.168.8.100:5001", "GET", headers, NULL); /* Flask Server */
    send_request("http://192.168.8.100:5002", "GET", headers, NULL); /* FastAPI Server */
    send_request("https://127.0.0.1:5003", "GET", headers, NULL); /* HttpHeaderFastApiServer Server */
    return 0;
}
