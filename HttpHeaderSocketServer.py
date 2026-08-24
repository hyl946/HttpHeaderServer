import hashlib
import os
import socket
import ssl
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8090"))
LISTEN_PORTS = (8090, 58888)  # 写死监听/抓 SYN 的端口
# 设置证书后启用 HTTPS；不设置则仍为明文 HTTP
TLS_CERT = os.environ.get("TLS_CERT", "")  # 例如 /path/to/fullchain.pem
TLS_KEY = os.environ.get("TLS_KEY", "")    # 例如 /path/to/privkey.pem
# 是否旁路抓 TCP SYN（Linux AF_PACKET，通常需要 root / CAP_NET_RAW）
CAPTURE_SYN = os.environ.get("CAPTURE_SYN", "1") not in ("0", "false", "False")

TLS_CERT = "tls/test.pem"
TLS_KEY = "tls/test.key"

# TLS GREASE values (RFC 8701)
_GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
           0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}

_TCP_OPT_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "WS",
    4: "SACK_PERM",
    5: "SACK",
    8: "TS",
}


@dataclass
class SynInfo:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ttl: int
    tos: int
    ip_id: int
    ip_flags_df: bool
    window: int
    seq: int
    options: list[str] = field(default_factory=list)
    option_kinds: list[int] = field(default_factory=list)
    mss: int | None = None
    wscale: int | None = None
    sack_permitted: bool = False
    tsval: int | None = None
    tsecr: int | None = None
    captured_at: float = 0.0


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


def _parse_tcp_options(opt_bytes: bytes) -> tuple[list[str], list[int], dict]:
    kinds: list[int] = []
    pretty: list[str] = []
    meta: dict = {
        "mss": None,
        "wscale": None,
        "sack_permitted": False,
        "tsval": None,
        "tsecr": None,
    }
    i = 0
    while i < len(opt_bytes):
        kind = opt_bytes[i]
        kinds.append(kind)
        name = _TCP_OPT_NAMES.get(kind, f"UNK({kind})")
        if kind == 0:  # EOL
            pretty.append(name)
            break
        if kind == 1:  # NOP
            pretty.append(name)
            i += 1
            continue
        if i + 1 >= len(opt_bytes):
            break
        length = opt_bytes[i + 1]
        if length < 2 or i + length > len(opt_bytes):
            pretty.append(f"{name}?")
            break
        data = opt_bytes[i + 2 : i + length]
        if kind == 2 and len(data) == 2:
            meta["mss"] = int.from_bytes(data, "big")
            pretty.append(f"MSS={meta['mss']}")
        elif kind == 3 and len(data) == 1:
            meta["wscale"] = data[0]
            pretty.append(f"WS={meta['wscale']}")
        elif kind == 4:
            meta["sack_permitted"] = True
            pretty.append("SACK_PERM")
        elif kind == 8 and len(data) == 8:
            meta["tsval"] = int.from_bytes(data[:4], "big")
            meta["tsecr"] = int.from_bytes(data[4:], "big")
            pretty.append(f"TS={meta['tsval']}/{meta['tsecr']}")
        else:
            pretty.append(f"{name}({data.hex()})" if data else name)
        i += length
    return pretty, kinds, meta


def _parse_ip_tcp_syn_payload(ip: bytes, listen_port: int) -> SynInfo | None:
    if len(ip) < 40:
        return None
    vihl = ip[0]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl + 20:
        return None
    if ip[9] != 6:  # TCP
        return None

    ttl = ip[8]
    tos = ip[1]
    ip_id = struct.unpack("!H", ip[4:6])[0]
    flags_frag = struct.unpack("!H", ip[6:8])[0]
    ip_flags_df = bool(flags_frag & 0x4000)
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])

    tcp = ip[ihl:]
    src_port, dst_port, seq, _ack, off_flags, window = struct.unpack("!HHIIHH", tcp[:16])
    data_off = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    # 只要客户端 SYN：SYN=1 ACK=0
    if (flags & 0x02) == 0 or (flags & 0x10) != 0:
        return None
    if dst_port not in LISTEN_PORTS:
        return None
    if data_off < 20 or len(tcp) < data_off:
        return None

    pretty, kinds, meta = _parse_tcp_options(tcp[20:data_off])
    return SynInfo(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        ttl=ttl,
        tos=tos,
        ip_id=ip_id,
        ip_flags_df=ip_flags_df,
        window=window,
        seq=seq,
        options=pretty,
        option_kinds=kinds,
        mss=meta["mss"],
        wscale=meta["wscale"],
        sack_permitted=meta["sack_permitted"],
        tsval=meta["tsval"],
        tsecr=meta["tsecr"],
        captured_at=time.time(),
    )


def parse_ipv4_tcp_syn(frame: bytes, listen_port: int) -> SynInfo | None:
    """解析纯 SYN。支持 Ethernet/VLAN/PPPoE/SLL/裸 IPv4（OpenWrt 常见）。"""
    payloads: list[bytes] = []

    def _add_ip_from_ethertype(buf: bytes, off: int, ethertype: int) -> None:
        if ethertype == 0x0800 and len(buf) > off:
            payloads.append(buf[off:])
        elif ethertype == 0x8864 and len(buf) >= off + 8:  # PPPoE
            ppp = struct.unpack("!H", buf[off + 6 : off + 8])[0]
            if ppp == 0x0021:  # IPv4
                payloads.append(buf[off + 8 :])

    # Ethernet (+ VLAN / PPPoE)
    if len(frame) >= 14:
        ethertype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            off = 18
        _add_ip_from_ethertype(frame, off, ethertype)

    # Linux SLL
    if len(frame) >= 16:
        ethertype = struct.unpack("!H", frame[14:16])[0]
        _add_ip_from_ethertype(frame, 16, ethertype)

    # 裸 IPv4（PPP/部分隧道）
    if frame and (frame[0] >> 4) == 4:
        payloads.append(frame)

    for ip in payloads:
        info = _parse_ip_tcp_syn_payload(ip, listen_port)
        if info:
            return info
    return None


class SynSniffer:
    """Linux AF_PACKET 旁路抓 SYN，按 (src_ip, src_port) 缓存供 accept 关联。"""

    def __init__(self, listen_port: int, max_entries: int = 4096, ttl_sec: float = 30.0):
        self.listen_port = listen_port
        self.max_entries = max_entries
        self.ttl_sec = ttl_sec
        self._cache: OrderedDict[tuple[str, int], SynInfo] = OrderedDict()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.enabled = False
        self.error: str | None = None

    def start(self) -> bool:
        if not hasattr(socket, "AF_PACKET"):
            self.error = "AF_PACKET unavailable (non-Linux?)"
            return False
        try:
            # ETH_P_ALL = 0x0003
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            raw.settimeout(1.0)
        except PermissionError as e:
            self.error = f"need CAP_NET_RAW/root: {e}"
            return False
        except OSError as e:
            self.error = str(e)
            return False

        self.enabled = True
        self._thread = threading.Thread(
            target=self._loop, args=(raw,), name="syn-sniffer", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()

    def _loop(self, raw: socket.socket) -> None:
        try:
            while not self._stop.is_set():
                try:
                    frame = raw.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                info = parse_ipv4_tcp_syn(frame, self.listen_port)
                if not info:
                    continue
                key = (info.src_ip, info.src_port)
                with self._lock:
                    self._cache[key] = info
                    self._cache.move_to_end(key)
                    while len(self._cache) > self.max_entries:
                        self._cache.popitem(last=False)
                    self._purge_locked()
                print(
                    f"SYN captured {info.src_ip}:{info.src_port} -> "
                    f"{info.dst_ip}:{info.dst_port} ttl={info.ttl} win={info.window}"
                )
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def _purge_locked(self) -> None:
        now = time.time()
        dead = [k for k, v in self._cache.items() if now - v.captured_at > self.ttl_sec]
        for k in dead:
            del self._cache[k]

    def pop(self, addr, retries: int = 20, delay: float = 0.05) -> SynInfo | None:
        key = (addr[0], int(addr[1]))
        for i in range(max(1, retries)):
            with self._lock:
                self._purge_locked()
                info = self._cache.pop(key, None)
            if info:
                return info
            if i + 1 < retries:
                time.sleep(delay)
        return None

    def get(self, addr) -> SynInfo | None:
        key = (addr[0], int(addr[1]))
        with self._lock:
            self._purge_locked()
            return self._cache.get(key)


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


def classify_os_from_syn(syn: SynInfo) -> tuple[str, float]:
    """
    根据 TCP SYN 指纹粗分 iOS / Android。
    返回 (标签, ios_score)，ios_score 为偏向 iOS 的概率约 0.0~1.0。
    """
    kinds = [k for k in syn.option_kinds if k != 0]
    score = 0.5  # 先验未知

    # option 顺序权重最大
    if len(kinds) >= 3 and kinds[0] == 2 and kinds[1] == 1 and kinds[2] == 3:
        # MSS, NOP, WS ... 典型 Apple/BSD
        score += 0.35
        if 8 in kinds and 4 in kinds and kinds.index(8) < kinds.index(4):
            score += 0.10
    elif len(kinds) >= 3 and kinds[0] == 2 and kinds[1] == 4 and kinds[2] == 8:
        # MSS, SACK, TS ... 典型 Linux/Android
        score -= 0.40

    # 辅助信号
    if syn.ip_id == 0:
        score += 0.08
    if syn.wscale is not None:
        if syn.wscale == 6:
            score += 0.05
        elif syn.wscale >= 8:
            score -= 0.05
    # 选项里 NOP 较多更像 BSD 填充
    nop_count = sum(1 for k in kinds if k == 1)
    if nop_count >= 2:
        score += 0.04
    elif nop_count == 0 and kinds[:3] == [2, 4, 8]:
        score -= 0.03

    score = max(0.0, min(1.0, score))

    if score >= 0.70:
        label = "ios"
    elif score <= 0.30:
        label = "android"
    else:
        label = "unknown"
    return label, round(score, 3)


def handle_client(
    conn: socket.socket,
    addr,
    hello: ClientHelloInfo | None = None,
    syn: SynInfo | None = None,
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
        if syn:
            body += "tcp syn信息\n"
            body += f"syn_from: {syn.src_ip}:{syn.src_port} -> {syn.dst_ip}:{syn.dst_port}\n"
            body += f"ip_ttl: {syn.ttl}\n"
            body += f"ip_tos: {syn.tos}\n"
            body += f"ip_id: {syn.ip_id}\n"
            body += f"ip_df: {syn.ip_flags_df}\n"
            body += f"tcp_window: {syn.window}\n"
            body += f"tcp_seq: {syn.seq}\n"
            body += f"tcp_mss: {syn.mss}\n"
            body += f"tcp_wscale: {syn.wscale}\n"
            body += f"tcp_sack_permitted: {syn.sack_permitted}\n"
            body += f"tcp_tsval: {syn.tsval}\n"
            body += f"tcp_tsecr: {syn.tsecr}\n"
            body += f"tcp_options: {syn.options}\n"
            body += f"tcp_option_kinds: {syn.option_kinds}\n"
            os_label, ios_score = classify_os_from_syn(syn)
            body += f"os_guess: {os_label}\n"
            body += f"ios_score: {ios_score}\n"
            body += "\n\n"
        elif CAPTURE_SYN:
            body += "tcp syn信息\n"
            body += "syn: (not captured)\n"
            body += "\n\n"

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
        body += f"{raw.decode('latin-1', errors='replace')}\n"
        body += "end:------------------------------\n"
        body = body.encode()

        print(body.decode("utf-8"))

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

    syn_sniffer: SynSniffer | None = None
    if CAPTURE_SYN:
        syn_sniffer = SynSniffer(LISTEN_PORTS[0])  # listen_port 参数已不再用于过滤
        if syn_sniffer.start():
            print(f"SYN capture enabled on ports {LISTEN_PORTS} (AF_PACKET)")
        else:
            print(f"SYN capture disabled: {syn_sniffer.error}")

    servers: list[socket.socket] = []
    for port in LISTEN_PORTS:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(32)
        servers.append(srv)
        print(f"raw header socket server on {scheme}://{HOST}:{port}/")
    if ssl_ctx:
        print(f"TLS enabled: cert={TLS_CERT} key={TLS_KEY}")

    import select
    while True:
        readable, _, _ = select.select(servers, [], [])
        for server in readable:
            conn, addr = server.accept()
            syn = syn_sniffer.pop(addr) if syn_sniffer and syn_sniffer.enabled else None
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
                    except Exception as e:
                        print(f"socket error from {addr}: {e}")
                    continue
            handle_client(conn, addr, hello, syn)


if __name__ == "__main__":
    main()