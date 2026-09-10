import socket
import threading

DEFAULT_CREDS = (("admin", "hunter2"), ("root", "toor"), ("svc", "svc123"))

BANNER = "SSH-2.0-OpenSSH_9.2_lab\r\n"


def _readline(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(1)
        except (OSError, socket.timeout):
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 4096:
            break
    return buf.decode("utf-8", "replace").strip()


def auth_session(host, port, pairs, timeout=5.0):
    results = []
    try:
        s = socket.create_connection((host, int(port)), timeout=2.0)
    except OSError:
        return results
    s.settimeout(timeout)
    try:
        _readline(s, timeout)
        for user, password in pairs:
            s.sendall(f"AUTH {user}:{password}\n".encode())
            line = _readline(s, timeout)
            matched = line.startswith("AUTH_SUCCESS") and f"user:{user}" in line
            results.append((user, password, matched))
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return results


def knock(host, port, timeout=5.0):
    s = socket.create_connection((host, int(port)), timeout=2.0)
    s.settimeout(timeout)
    try:
        _readline(s, timeout)
        s.sendall(b"KNOCK\n")
        return _readline(s, timeout)
    finally:
        try:
            s.close()
        except OSError:
            pass


class LabSSH:
    def __init__(self, creds=DEFAULT_CREDS):
        self.creds = dict(creds)
        self._sock = None
        self._thread = None
        self._running = False

    def spawn(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.endpoint()

    def endpoint(self):
        host, port = self._sock.getsockname()[:2]
        return f"{host}:{port}"

    def _accept_loop(self):
        while self._running:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, conn):
        with conn:
            try:
                conn.sendall(BANNER.encode())
                while True:
                    line = _readline(conn)
                    if not line:
                        break
                    if line.startswith("AUTH "):
                        rest = line[len("AUTH "):]
                        if ":" in rest:
                            user, password = rest.split(":", 1)
                            if self.creds.get(user) == password:
                                conn.sendall(f"AUTH_SUCCESS:user:{user}\n".encode())
                                continue
                        conn.sendall(b"AUTH_FAIL\n")
                    elif line.strip() == "KNOCK":
                        conn.sendall(b"KNOCK_OK:lab-knock-sim\n")
                    elif line.strip() == "QUIT":
                        break
            except OSError:
                pass

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass