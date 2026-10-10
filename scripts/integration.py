"""Local-only HTTP/STUN/TURN smoke test, independent of private desktop source."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def docker(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.STDOUT).decode().strip()


def http(path, credential=None, body=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    request = urllib.request.Request("http://127.0.0.1:18088" + path,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    assert response.status == expected, (path, response.status, expected)
    return json.load(response)


COOKIE = 0x2112A442


def attr(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + bytes((-len(value)) % 4)


def stun(sock, kind, attributes=b"", key=None):
    transaction = secrets.token_bytes(12)
    header = struct.pack("!HHI", kind, len(attributes) + (24 if key else 0), COOKIE) + transaction
    packet = header + attributes
    if key:
        packet += attr(8, hmac.new(key, packet, hashlib.sha1).digest())
    sock.sendto(packet, ("127.0.0.1", 3479))
    data = sock.recv(65536)
    assert data[8:20] == transaction
    fields = {}
    offset = 20
    while offset + 4 <= len(data):
        tag, length = struct.unpack("!HH", data[offset:offset+4])
        fields[tag] = data[offset+4:offset+4+length]
        offset += 4 + ((length + 3) // 4) * 4
    return struct.unpack("!H", data[:2])[0], fields


with tempfile.TemporaryDirectory(prefix="veil-server-test-") as temporary:
    folder = Path(temporary)
    os.chmod(folder, 0o755)
    (folder / "data").mkdir(mode=0o777)
    os.chmod(folder / "data", 0o777)
    secret = secrets.token_hex(32)
    metrics = secrets.token_hex(32)
    (folder / "turn-secret").write_text(secret)
    (folder / "metrics-secret").write_text(metrics)
    config = "\n".join([
        "listening-port=3479", "realm=veil-test", "use-auth-secret",
        "static-auth-secret=" + secret, "external-ip=127.0.0.1",
        "min-port=40000", "max-port=40040", "total-quota=32", "user-quota=4",
        "allow-loopback-peers", "no-cli", "no-tls", "no-dtls", "relay-threads=1",
        "prometheus", "prometheus-address=0.0.0.0", "prometheus-port=9641",
        "log-file=stdout",
    ])
    (folder / "turn.conf").write_text(config)
    suffix = secrets.token_hex(4)
    turn_name, signal_name = "veil-turn-" + suffix, "veil-signal-" + suffix
    try:
        docker("run", "--rm", "-d", "--name", turn_name,
               "-p", "127.0.0.1:3479:3479/udp", "-p", "127.0.0.1:19641:9641",
               "-v", str(folder / "turn.conf") + ":/test.conf:ro",
               "coturn/coturn:4.18.0-r0", "-c", "/test.conf")
        docker("run", "--rm", "-d", "--name", signal_name,
               "-p", "127.0.0.1:18088:8080", "-v", str(folder) + ":/test",
               "-e", "LISTEN=0.0.0.0:8080", "-e", "HOST_DB=/test/data/hosts.sqlite",
               "-e", "TURN_SECRET_FILE=/test/turn-secret", "-e", "METRICS_SECRET_FILE=/test/metrics-secret",
               "-e", "STUN_URLS=stun:127.0.0.1:3479", "-e", "TURN_URLS=turn:127.0.0.1:3479",
               os.environ.get("VEIL_SERVER_IMAGE", "veil-server:development"))
        for attempt in range(50):
            try:
                http("/health")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        host = docker("exec", signal_name, "veil-server", "issue", "test")
        http("/v2/sessions", "0" * 64, {"clientId": 1}, 401)
        room = http("/v2/sessions", host, {"clientId": 1})
        invite_id, admission = secrets.token_hex(16), secrets.token_hex(32)
        http("/v2/sessions/" + room["sessionId"] + "/invitations", room["ticket"],
             {"inviteId": invite_id, "admissionHash": hashlib.sha256(admission.encode()).hexdigest(),
              "expiresAt": int(time.time() * 1000) + 600000})
        join = {"sessionId": room["sessionId"], "inviteId": invite_id, "admission": admission, "clientId": 2}
        guest = http("/v2/join", None, join)
        http("/v2/join", None, join, 401)
        assert http("/v2/metrics", metrics)["relayCredentialsIssued"] == 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            # A successful STUN binding never creates a TURN allocation.
            assert stun(sock, 1)[0] == 0x101
            requested = attr(0x19, b"\x11\0\0\0")
            kind, challenge = stun(sock, 3, requested)
            assert kind == 0x113 and challenge[9][2:4] == b"\x04\x01"
            relay_body = {"sessionId": room["sessionId"], "inviteId": invite_id}
            relay = http("/v2/relay", guest["ticket"], relay_body)
            assert relay == http("/v2/relay", guest["ticket"], relay_body)
            expected = base64.b64encode(hmac.new(secret.encode(), relay["username"].encode(), hashlib.sha1).digest()).decode()
            assert hmac.compare_digest(relay["credential"], expected)
            realm, nonce = challenge[0x14], challenge[0x15]
            key = hashlib.md5(relay["username"].encode() + b":" + realm + b":" + relay["credential"].encode()).digest()
            auth = attr(6, relay["username"].encode()) + attr(0x14, realm) + attr(0x15, nonce)
            assert stun(sock, 3, requested + auth, key)[0] == 0x103
            metric_text = urllib.request.urlopen('http://127.0.0.1:19641/metrics', timeout=5).read().decode()
            assert sum(float(line.split()[-1]) for line in metric_text.splitlines() if line.startswith('turn_total_allocations{')) >= 1
            # Explicit allocation deletion, rather than assuming credential expiry cleans up.
            assert stun(sock, 4, attr(0x0D, struct.pack("!I", 0)) + auth, key)[0] == 0x104
            for attempt in range(50):
                metric_text = urllib.request.urlopen('http://127.0.0.1:19641/metrics', timeout=5).read().decode()
                if sum(float(line.split()[-1]) for line in metric_text.splitlines() if line.startswith('turn_total_allocations{')) == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError('TURN allocation remained after explicit deletion')
        docker("exec", signal_name, "veil-server", "revoke", "test")
        http("/v2/relay", guest["ticket"], relay_body, 401)
        print("PASS: container HTTP authentication, single use, lazy/cached TURN grants, actual STUN/allocate/delete and revocation")
    finally:
        for name in (signal_name, turn_name):
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
