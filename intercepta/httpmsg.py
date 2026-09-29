"""Utilitarios de (des)serializacao de mensagens HTTP/1.x."""
import gzip
import zlib

MAX_HEAD = 8 * 1024 * 1024


def recv_head(sock):
    """Le ate o fim dos cabecalhos. Retorna (first_line, headers, leftover)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_HEAD:
            break
    if b"\r\n\r\n" not in buf:
        return None, None, buf
    block, _, rest = buf.partition(b"\r\n\r\n")
    first, headers = parse_block(block)
    return first, headers, rest


def parse_block(block):
    if isinstance(block, str):
        block = block.encode("latin-1", "replace")
    lines = block.replace(b"\r\n", b"\n").split(b"\n")
    first = lines[0].decode("latin-1").strip()
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if b":" in line:
            key, _, value = line.partition(b":")
            headers.append((key.decode("latin-1").strip(), value.decode("latin-1").strip()))
    return first, headers


def parse_message(raw):
    """Separa uma mensagem completa em (first_line, headers, body)."""
    if isinstance(raw, str):
        raw = raw.encode("latin-1", "replace")
    if b"\r\n\r\n" in raw:
        block, _, body = raw.partition(b"\r\n\r\n")
    elif b"\n\n" in raw:
        block, _, body = raw.partition(b"\n\n")
    else:
        return parse_block(raw)[0], parse_block(raw)[1], b""
    first, headers = parse_block(block)
    return first, headers, body


def serialize(first, headers, body):
    if isinstance(first, bytes):
        first = first.decode("latin-1")
    head = first + "\r\n" + "\r\n".join(f"{k}: {v}" for k, v in headers) + "\r\n\r\n"
    return head.encode("latin-1", "replace") + (body or b"")


def get_header(headers, name):
    low = name.lower()
    for key, value in headers:
        if key.lower() == low:
            return value
    return None


def set_header(headers, name, value):
    low = name.lower()
    for i, (key, _) in enumerate(headers):
        if key.lower() == low:
            headers[i] = (key, value)
            return headers
    headers.append((name, value))
    return headers


def del_header(headers, name):
    low = name.lower()
    return [(k, v) for (k, v) in headers if k.lower() != low]


def read_body(sock, headers, leftover):
    """Le o corpo de uma requisicao a partir de Content-Length."""
    length = get_header(headers, "Content-Length")
    if not length:
        return b""
    try:
        size = int(length)
    except ValueError:
        return b""
    data = leftover or b""
    while len(data) < size:
        chunk = sock.recv(min(65536, size - len(data)))
        if not chunk:
            break
        data += chunk
    return data[:size]


def _read_chunked(sock, leftover):
    data = leftover or b""
    out = bytearray()

    def fill(target):
        nonlocal data
        while len(data) < target:
            chunk = sock.recv(65536)
            if not chunk:
                raise IOError("conexao encerrada durante resposta chunked")
            data += chunk

    while True:
        idx = data.find(b"\r\n")
        while idx == -1:
            fill(len(data) + 1)
            idx = data.find(b"\r\n")
        line = data[:idx]
        data = data[idx + 2:]
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            raise IOError("chunk invalido")
        if size == 0:
            break
        fill(size + 2)
        out += data[:size]
        data = data[size + 2:]
    return bytes(out)


def read_response(sock, method="GET"):
    """Le uma resposta completa. Retorna (status, reason, headers, body)."""
    first, headers, leftover = recv_head(sock)
    if not first:
        raise IOError("servidor remoto nao devolveu resposta")
    parts = first.split(" ", 2)
    if len(parts) < 2:
        raise IOError("resposta HTTP invalida: %r" % first)
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    te = (get_header(headers, "Transfer-Encoding") or "").lower()
    cl = get_header(headers, "Content-Length")

    if method.upper() == "HEAD" or status in (204, 304):
        return status, reason, headers, b""

    if "chunked" in te:
        body = _read_chunked(sock, leftover)
        headers = del_header(headers, "Transfer-Encoding")
        headers = del_header(headers, "Content-Length")
        set_header(headers, "Content-Length", str(len(body)))
        return status, reason, headers, body

    if cl is not None:
        try:
            size = int(cl)
        except ValueError:
            size = 0
        data = leftover or b""
        while len(data) < size:
            chunk = sock.recv(min(65536, size - len(data)))
            if not chunk:
                break
            data += chunk
        return status, reason, headers, data[:size]

    # sem tamanho: le ate o servidor fechar
    data = leftover or b""
    while True:
        try:
            chunk = sock.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 512 * 1024 * 1024:
            break
    return status, reason, headers, data


def decode_body(headers, body):
    """Descomprime o corpo para exibicao (gzip/deflate). Retorna (texto, ok)."""
    if not body:
        return "", True
    enc = (get_header(headers, "Content-Encoding") or "").lower()
    data = body
    try:
        if "gzip" in enc:
            data = gzip.decompress(body)
        elif "deflate" in enc:
            try:
                data = zlib.decompress(body)
            except zlib.error:
                data = zlib.decompress(body, -zlib.MAX_WBITS)
        elif "br" in enc:
            try:
                import brotli  # opcional
                data = brotli.decompress(body)
            except Exception:
                return "<corpo comprimido com brotli - instale 'brotli' para ver>", False
    except Exception as exc:
        return "<falha ao descomprimir %s: %s>" % (enc, exc), False
    return data.decode("utf-8", "replace"), True


def pretty(raw_bytes):
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1")
