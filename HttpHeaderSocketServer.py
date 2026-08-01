import hashlib
import os
import socket
import ssl
from dataclasses import dataclass, field

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8090"))
# 设置证书后启用 HTTPS；不设置则仍为明文 HTTP
TLS_CERT = os.environ.get("TLS_CERT", "")  # 例如 /path/to/fullchain.pem
TLS_KEY = os.environ.get("TLS_KEY", "")    # 例如 /path/to/privkey.pem

TLS_CERT = "tls/test.pem"
TLS_KEY = "tls/test.key"

# TLS GREASE values (RFC 8701)
_GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
           0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}


@dataclass
class ClientHelloInfo:
    record_version: int = 0
    client_version: int = 0
    cipher_suites: list[int] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    sni: str | None = None
    ja3: str = ""
    ja3_hash: str = ""
    raw_hex: str = ""


class BioSSLConnection:
    """
    用 MemoryBIO 做 TLS：可先解析已读的 ClientHello，再把同样字节喂给 OpenSSL。
    行为近似 SSLSocket（recv/sendall + 协商信息查询）。
    """

    def __init__(self, sock: socket.socket, ctx: ssl.SSLContext, prefix: bytes):
        self._sock = sock
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl = ctx.wrap_bio(self._incoming, self._outgoing, server_side=True)
        if prefix:
            self._incoming.write(prefix)
        self._handshake()

    def _pump_out(self) -> None:
        while True:
            data = self._outgoing.read()
            if not data:
                return
            self._sock.sendall(data)

    def _handshake(self) -> None:
        while True:
            try:
                self._ssl.do_handshake()
                self._pump_out()
                return
            except ssl.SSLWantReadError:
                self._pump_out()
                chunk = self._sock.recv(16384)
                if not chunk:
                    raise ssl.SSLError("EOF during handshake")
                self._incoming.write(chunk)
            except ssl.SSLWantWriteError:
                self._pump_out()

    def recv(self, buflen: int = 4096, flags: int = 0) -> bytes:
        while True:
            try:
                data = self._ssl.read(buflen)
                self._pump_out()
                return data
            except ssl.SSLWantReadError:
                self._pump_out()
                chunk = self._sock.recv(16384)
                if not chunk:
                    return b""
                self._incoming.write(chunk)
            except ssl.SSLWantWriteError:
                self._pump_out()
            except ssl.SSLZeroReturnError:
                return b""

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while len(view):
            try:
                n = self._ssl.write(view)
                self._pump_out()
                view = view[n:]
            except ssl.SSLWantReadError:
                self._pump_out()
                chunk = self._sock.recv(16384)
                if not chunk:
                    raise BrokenPipeError("peer closed during send")
                self._incoming.write(chunk)
            except ssl.SSLWantWriteError:
                self._pump_out()

    def version(self):
        return self._ssl.version()

    def cipher(self):
        return self._ssl.cipher()

    def selected_alpn_protocol(self):
        return self._ssl.selected_alpn_protocol()

    def compression(self):
        return self._ssl.compression()

    @property
    def session_reused(self):
        return self._ssl.session_reused

    @property
    def session(self):
        return self._ssl.session

    def shutdown(self, how: int) -> None:
        try:
            self._ssl.unwrap()
            self._pump_out()
        except Exception:
            pass
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def make_ssl_context() -> ssl.SSLContext | None:
    if not TLS_CERT or not TLS_KEY:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    ctx.set_alpn_protocols(["http/1.1", "h2"])
    return ctx


def _u16(data: bytes, off: int) -> int:
    return (data[off] << 8) | data[off + 1]


def _is_grease(v: int) -> bool:
    return v in _GREASE


def parse_client_hello(data: bytes) -> ClientHelloInfo | None:
    """从 TLS record 缓冲中解析 ClientHello（含 SNI / JA3）。"""
    if len(data) < 5 or data[0] != 0x16:
        return None

    record_version = _u16(data, 1)
    record_len = _u16(data, 3)
    if len(data) < 5 + record_len:
        return None

    hs = data[5 : 5 + record_len]
    if len(hs) < 4 or hs[0] != 0x01:  # handshake type ClientHello
        return None

    hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
    body = hs[4 : 4 + hs_len]
    if len(body) < 34:
        return None

    info = ClientHelloInfo(record_version=record_version)
    info.raw_hex = data[: 5 + record_len].hex()
    pos = 0
    info.client_version = _u16(body, pos)
    pos += 2
    pos += 32  # random

    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return None

    cs_len = _u16(body, pos)
    pos += 2
    if pos + cs_len > len(body) or cs_len % 2:
        return None
    for i in range(0, cs_len, 2):
        info.cipher_suites.append(_u16(body, pos + i))
    pos += cs_len

    if pos >= len(body):
        return None
    comp_len = body[pos]
    pos += 1
    if pos + comp_len > len(body):
        return None
    info.compression_methods = list(body[pos : pos + comp_len])
    pos += comp_len

    if pos == len(body):
        _fill_ja3(info)
        return info
    if pos + 2 > len(body):
        return None

    ext_total = _u16(body, pos)
    pos += 2
    ext_end = pos + ext_total
    if ext_end > len(body):
        return None

    while pos + 4 <= ext_end:
        ext_type = _u16(body, pos)
        ext_len = _u16(body, pos + 2)
        pos += 4
        if pos + ext_len > ext_end:
            break
        ext_data = body[pos : pos + ext_len]
        pos += ext_len
        info.extensions.append(ext_type)

        if ext_type == 0 and len(ext_data) >= 5:  # server_name
            # list_len(2) + name_type(1) + name_len(2) + name
            name_type = ext_data[2]
            name_len = _u16(ext_data, 3)
            if name_type == 0 and 5 + name_len <= len(ext_data):
                info.sni = ext_data[5 : 5 + name_len].decode("ascii", errors="replace")
        elif ext_type == 10 and len(ext_data) >= 2:  # supported_groups
            glist = _u16(ext_data, 0)
            for i in range(2, 2 + glist, 2):
                if i + 1 < len(ext_data):
                    info.supported_groups.append(_u16(ext_data, i))
        elif ext_type == 11 and len(ext_data) >= 1:  # ec_point_formats
            n = ext_data[0]
            info.ec_point_formats = list(ext_data[1 : 1 + n])
        elif ext_type == 13 and len(ext_data) >= 2:  # signature_algorithms
            slen = _u16(ext_data, 0)
            for i in range(2, 2 + slen, 2):
                if i + 1 < len(ext_data):
                    info.signature_algorithms.append(_u16(ext_data, i))
        elif ext_type == 16 and len(ext_data) >= 2:  # ALPN
            i = 2
            while i < len(ext_data):
                n = ext_data[i]
                i += 1
                info.alpn.append(ext_data[i : i + n].decode("ascii", errors="replace"))
                i += n
        elif ext_type == 43 and len(ext_data) >= 1:  # supported_versions
            n = ext_data[0]
            for i in range(1, 1 + n, 2):
                if i + 1 < len(ext_data):
                    info.supported_versions.append(_u16(ext_data, i))

    _fill_ja3(info)
    return info


def _fill_ja3(info: ClientHelloInfo) -> None:
    ciphers = "-".join(str(c) for c in info.cipher_suites if not _is_grease(c))
    exts = "-".join(str(e) for e in info.extensions if not _is_grease(e))
    groups = "-".join(str(g) for g in info.supported_groups if not _is_grease(g))
    formats = "-".join(str(f) for f in info.ec_point_formats)
    # JA3 使用 ClientHello.client_version（不是 record version）
    info.ja3 = f"{info.client_version},{ciphers},{exts},{groups},{formats}"
    info.ja3_hash = hashlib.md5(info.ja3.encode()).hexdigest()


def read_client_hello_record(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """读完整的第一条 TLS handshake record（通常即 ClientHello）。"""
    old = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        buf = b""
        while len(buf) < 5:
            chunk = sock.recv(5 - len(buf))
            if not chunk:
                break
            buf += chunk
        if len(buf) < 5:
            return buf
        need = 5 + _u16(buf, 3)
        while len(buf) < need:
            chunk = sock.recv(need - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf
    finally:
        sock.settimeout(old)


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


def _fmt_u16_list(vals: list[int]) -> str:
    return ",".join(f"0x{v:04x}({v})" for v in vals)


def handle_client(
    conn: socket.socket,
    addr,
    hello: ClientHelloInfo | None = None,
) -> None:
    try:
        raw = read_http_head(conn)
        if not raw:
            return

        request_line, headers, lines_list = parse_raw_headers(raw)
        # print(f"=== from {addr} ===")
        # print(f"request_line: {request_line}")
        # print("headers (raw order / raw casing):")
        # for line in lines_list:
        #     print(line)
        # print()

        src_ip = addr[0]
        src_port = addr[1]
        headers_str = "\r\n".join(lines_list)

        body = ""
        if isinstance(conn, (ssl.SSLSocket, BioSSLConnection)):
            session = conn.session
            body += "tls信息 (协商后)\n"
            body += f"tls_version: {conn.version()}\n"
            body += f"tls_cipher: {conn.cipher()}\n"
            body += f"tls_alpn: {conn.selected_alpn_protocol()}\n"
            body += f"tls_compression: {conn.compression()}\n"
            body += f"tls_session_reused: {conn.session_reused}\n"
            body += f"tls_session_id: {session.id.hex() if session else None}\n"
            body += f"tls_session_has_ticket: {session.has_ticket if session else None}\n"
            body += f"tls_session_ticket_lifetime_hint: {session.ticket_lifetime_hint if session else None}\n"
            body += "\n\n"

        if hello:
            body += "tls信息 (ClientHello)\n"
            body += f"sni: {hello.sni}\n"
            body += f"record_version: 0x{hello.record_version:04x}\n"
            body += f"client_version: 0x{hello.client_version:04x}\n"
            body += f"supported_versions: {_fmt_u16_list(hello.supported_versions)}\n"
            body += f"cipher_suites: {_fmt_u16_list(hello.cipher_suites)}\n"
            body += f"extensions: {_fmt_u16_list(hello.extensions)}\n"
            body += f"supported_groups: {_fmt_u16_list(hello.supported_groups)}\n"
            body += f"ec_point_formats: {_fmt_u16_list(hello.ec_point_formats)}\n"
            body += f"signature_algorithms: {_fmt_u16_list(hello.signature_algorithms)}\n"
            body += f"alpn_offered: {hello.alpn}\n"
            body += f"ja3: {hello.ja3}\n"
            body += f"ja3_hash: {hello.ja3_hash}\n"
            body += "\n\n"

        body += f"src_ip: {src_ip}:{src_port}\n\n\n"
        body += "解析的请求头: \n"
        body += "start:------------------------------\n"
        body += f"{headers_str}\n"
        body += "end:------------------------------\n"
        body += "\n\n"

        body += "原始报文: \n"
        body += "start:------------------------------\n"
        body += f"{raw.decode('utf-8')}\n"
        body += "end:------------------------------\n"
        body = body.encode()

        print(body)

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
            hello: ClientHelloInfo | None = None
            if ssl_ctx:
                try:
                    # 握手前先读 ClientHello，解析 SNI/JA3，再经 MemoryBIO 喂给 OpenSSL
                    prefix = read_client_hello_record(conn)
                    hello = parse_client_hello(prefix)
                    if hello:
                        print(
                            f"ClientHello from {addr}: sni={hello.sni} "
                            f"ja3={hello.ja3_hash}"
                        )
                    conn = BioSSLConnection(conn, ssl_ctx, prefix)
                except ssl.SSLError as e:
                    print(f"tls handshake failed from {addr}: {e}")
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
                except OSError as e:
                    print(f"socket error from {addr}: {e}")
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
            handle_client(conn, addr, hello)


if __name__ == "__main__":
    main()
