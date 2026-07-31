import os
import socket
import ssl

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8090"))
# 设置证书后启用 HTTPS；不设置则仍为明文 HTTP
TLS_CERT = os.environ.get("TLS_CERT", "")  # 例如 /path/to/fullchain.pem
TLS_KEY = os.environ.get("TLS_KEY", "")    # 例如 /path/to/privkey.pem

TLS_CERT = "tls/test.pem"
TLS_KEY = "tls/test.key"

def make_ssl_context() -> ssl.SSLContext | None:
    if not TLS_CERT or not TLS_KEY:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    return ctx


def read_http_head(conn: socket.socket, bufsize: int = 4096) -> bytes:
    """读到 header 结束标记 \\r\\n\\r\\n 为止（TLS 时读的是解密后的 HTTP）。"""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(bufsize)
        if not chunk:
            break
        data += chunk
        if len(data) > 1024 * 1024:
            raise ValueError("request head too large")
    return data


def parse_raw_headers(head: bytes) -> tuple[str, list[tuple[str, str]], list[str]]:
    """
    按原始字节解析请求行和 headers。
    保留 header 名/值的原始大小写与出现顺序；同名头不会合并。
    """
    head_part, _, _ = head.partition(b"\r\n\r\n")
    lines = head_part.split(b"\r\n")
    if not lines:
        return "", [], []

    request_line = lines[0].decode("latin-1", errors="replace")
    headers: list[tuple[str, str]] = []
    lines_list: list[str] = []
    for line in lines[1:]:
        lines_list.append(line.decode("latin-1", errors="replace"))
        if not line or b":" not in line:
            continue
        name, value = line.split(b":", 1)
        # 只去掉值左侧空格（HTTP 允许 name: value），不改大小写
        headers.append(
            (
                name.decode("latin-1", errors="replace"),
                value.decode("latin-1", errors="replace").lstrip(" \t"),
            )
        )
    return request_line, headers, lines_list


def handle_client(conn: socket.socket, addr) -> None:
    try:
        raw = read_http_head(conn)
        if not raw:
            return

        request_line, headers, lines_list = parse_raw_headers(raw)
        print(f"=== from {addr} ===")
        print(f"request_line: {request_line}")
        print("headers (raw order / raw casing):")
        for line in lines_list:
            print(line)
        print()

        src_ip = addr[0]
        src_port = addr[1]
        headers_str = "\r\n".join(lines_list)

        body = f"src_ip: {src_ip}:{src_port}\nheaders: \nstart:------------------------------\n{headers_str}\nend:------------------------------\n".encode()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        conn.sendall(resp)
    except ssl.SSLError as e:
        print(f"tls error from {addr}: {e}")
    except Exception as e:
        print(f"error from {addr}: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main() -> None:
    ssl_ctx = make_ssl_context()
    scheme = "https" if ssl_ctx else "http"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(32)
        print(f"raw header socket server on {scheme}://{HOST}:{PORT}/")
        if ssl_ctx:
            print(f"TLS enabled: cert={TLS_CERT} key={TLS_KEY}")

        while True:
            conn, addr = server.accept()
            if ssl_ctx:
                try:
                    # 在本进程做 TLS 终结：解密后再解析 HTTP，可保留明文 header 顺序/大小写
                    conn = ssl_ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError as e:
                    print(f"tls handshake failed from {addr}: {e}")
                    conn.close()
                    continue
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
