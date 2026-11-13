"""Private, bounded fixture for the actual ProvisioningClient constructor.

Only fixed public result codes leave this process. A fresh private directory
owns all keys, request captures and CA configuration; all listeners are
loopback-only. Python's verifying TLS client is independent of reqwest.
"""
import contextlib
import datetime
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import threading


class FixtureFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise FixtureFailure(code)


def openssl(*arguments):
    result = subprocess.run(
        ["openssl", *map(str, arguments)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
    )
    require(result.returncode == 0, "certificate-generation-failed")


def certificates(root):
    for name in ("ca", "unrelated"):
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", root / (name + ".key"), "-out", root / (name + ".pem"),
                "-subj", "/CN=Native TLS fixture " + name, "-addext",
                "basicConstraints=critical,CA:TRUE", "-addext",
                "keyUsage=critical,keyCertSign,cRLSign")
    (root / "index").write_text("")
    (root / "serial").write_text("01\n")
    (root / "ca.cnf").write_text(f"""[ca]
default_ca = fixture
[fixture]
database = {root / 'index'}
serial = {root / 'serial'}
new_certs_dir = {root}
certificate = {root / 'ca.pem'}
private_key = {root / 'ca.key'}
default_md = sha256
policy = names
unique_subject = no
[names]
commonName = supplied
""")
    now = datetime.datetime.now(datetime.timezone.utc)
    for name, hostname, days in (("valid", "localhost", 1),
                                 ("wrong_san", "invalid.example", 1),
                                 ("expired", "localhost", -1)):
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
                root / (name + ".key"), "-out", root / (name + ".csr"),
                "-subj", "/CN=" + name)
        extensions = root / (name + ".ext")
        extensions.write_text("[leaf]\nbasicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + hostname + "\n")
        start = (now - datetime.timedelta(days=2)).strftime("%Y%m%d%H%M%SZ")
        end = (now + datetime.timedelta(days=days)).strftime("%Y%m%d%H%M%SZ")
        openssl("ca", "-batch", "-notext", "-config", root / "ca.cnf",
                "-in", root / (name + ".csr"), "-out", root / (name + ".pem"),
                "-startdate", start, "-enddate", end, "-extfile", extensions,
                "-extensions", "leaf")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_arguments):
        pass

    def do_GET(self):
        self.server.requests += 1
        if self.path == "/control":
            self.server.controls += 1
        elif self.path == "/redirect-target":
            self.server.redirects += 1
        elif re.fullmatch(r"/v1/agent/nest/provisioning-sessions/[0-9a-f-]{36}/plan", self.path):
            headers = ("x-tiaris-request-id", "x-tiaris-timestamp", "x-tiaris-signature")
            if (any(not self.headers.get(name) or len(self.headers[name]) > 256 for name in headers)
                    or self.headers.get("x-tiaris-nest-provisioning-secret") is not None
                    or self.headers.get("Content-Length") not in (None, "0")):
                self.send_error(400)
                return
            capture = {"path": self.path, "request_id": self.headers[headers[0]],
                       "timestamp": self.headers[headers[1]], "signature": self.headers[headers[2]]}
            descriptor = os.open(self.server.capture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                json.dump(capture, output)
            self.server.plans += 1
            if self.server.redirect:
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        else:
            self.send_error(404)
            return
        body = b'{"code":"native_tls_unclaimed"}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, context):
        super().__init__(("127.0.0.1", 0), Handler)
        self.context = context
        self.requests = self.controls = self.plans = self.redirects = 0
        self.redirect = False
        self.capture = None

    def get_request(self):
        connection, address = self.socket.accept()
        connection.settimeout(3)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise

    def handle_error(self, *_arguments):
        # Do not expose arbitrary request data or exception text.
        pass


@contextlib.contextmanager
def serve(root, name, owned, redirect=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / (name + ".pem"), root / (name + ".key"))
    server = Server(context)
    server.redirect = redirect
    thread = threading.Thread(target=server.serve_forever, daemon=False)
    owned.append((server, thread))
    try:
        thread.start()
        yield server
    finally:
        if thread.is_alive():
            server.shutdown()
        server.server_close()
        if thread.ident is not None:
            thread.join(timeout=5)
        require(not thread.is_alive(), "listener-cleanup-failed")


def control(root, server, certificate="ca", reject=False):
    context = ssl.create_default_context(cafile=root / (certificate + ".pem"))
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
            "control-verification-disabled")
    connection = http.client.HTTPSConnection("localhost", server.server_port,
                                           context=context, timeout=3)
    before = server.controls
    try:
        try:
            connection.request("GET", "/control")
            response = connection.getresponse()
        except ssl.SSLCertVerificationError:
            require(reject and server.controls == before, "control-certificate-rejected")
            return
        require(not reject and response.status == 401 and
                response.read(256) == b'{"code":"native_tls_unclaimed"}',
                "control-response-rejected")
    finally:
        connection.close()


def child(root, server, executable, test_name, mode, certificate="ca"):
    capture = root / (mode + "-request.json")
    server.capture = capture
    before = server.plans
    before_requests = server.requests
    environment = {name: os.environ[name] for name in ("PATH", "LD_LIBRARY_PATH") if name in os.environ}
    environment.update({"RUST_BACKTRACE": "0", "SSL_CERT_FILE": str(root / (certificate + ".pem")),
                        "TIARIS_NATIVE_TLS_CASE": json.dumps({"mode": mode,
                            "origin": ("http" if mode == "http" else "https") + "://localhost:" + str(server.server_port),
                            "capture": str(capture)})})
    result = subprocess.run([executable, "--exact", test_name, "--ignored", "--nocapture"],
                            env=environment, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    if result.returncode != 0:
        for code in ("tls-unknown-issuer", "tls-name-mismatch", "tls-expired", "transport-unclassified"):
            if ("NATIVE_TLS_WITNESS " + code).encode() in result.stdout:
                print("NATIVE_TLS_WITNESS " + code, flush=True)
                break
        require(server.requests == before_requests and server.plans == before
                and not capture.exists(), "failed-client-reached-http")
        print("NATIVE_TLS_WITNESS native-zero-http-confirmed", flush=True)
        raise FixtureFailure("native-" + mode + "-rejected")
    require(b"NATIVE_TLS_CHILD_PASS" in result.stdout, "native-child-did-not-run")
    expected = 1 if mode in ("trusted", "redirect") else 0
    require(server.requests - before_requests == expected and server.plans - before == expected
            and capture.exists() == bool(expected),
            "native-http-count-rejected")
    require(server.redirects == 0, "native-followed-redirect")
    print("NATIVE_TLS_WITNESS " + mode + "-passed", flush=True)


def main():
    require(len(sys.argv) == 3, "fixture-arguments-rejected")
    os.umask(0o077)
    signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(FixtureFailure("fixture-timeout")))
    for termination in (signal.SIGTERM, signal.SIGINT):
        signal.signal(termination, lambda *_args: (_ for _ in ()).throw(FixtureFailure("fixture-interrupted")))
    signal.alarm(180)
    owned = []
    root = None
    try:
        with tempfile.TemporaryDirectory(prefix="tiaris-native-tls-") as directory:
            root = Path(directory)
            certificates(root)
            with contextlib.ExitStack() as stack:
                valid = stack.enter_context(serve(root, "valid", owned))
                wrong = stack.enter_context(serve(root, "wrong_san", owned))
                expired = stack.enter_context(serve(root, "expired", owned))
                redirect = stack.enter_context(serve(root, "valid", owned, redirect=True))
                control(root, valid)
                control(root, valid, certificate="unrelated", reject=True)
                control(root, wrong, reject=True)
                control(root, expired, reject=True)
                print("NATIVE_TLS_WITNESS independent-controls-passed", flush=True)
                for server, mode, certificate in ((valid, "trusted", "ca"),
                                                  (valid, "unrelated", "unrelated"),
                                                  (wrong, "wrong_san", "ca"),
                                                  (expired, "expired", "ca"),
                                                  (valid, "http", "ca"),
                                                  (redirect, "redirect", "ca")):
                    child(root, server, sys.argv[1], sys.argv[2], mode, certificate)
    finally:
        signal.alarm(0)
        require(root is not None and not root.exists()
                and all(server.fileno() == -1 and not thread.is_alive() for server, thread in owned),
                "cleanup-incomplete")
        print("NATIVE_TLS_WITNESS cleanup-complete", flush=True)


if __name__ == "__main__":
    try:
        main()
    except FixtureFailure as error:
        print("NATIVE_TLS_WITNESS " + str(error), flush=True)
        sys.exit(1)
    except BaseException:
        print("NATIVE_TLS_WITNESS fixture-unclassified", flush=True)
        sys.exit(1)
