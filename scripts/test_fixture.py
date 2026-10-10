"""Public HKDF compatibility vector; every value is a documented test secret."""
import hashlib
import hmac
import json
from pathlib import Path

fixture = json.loads((Path(__file__).parent.parent / "fixtures/signaling-v2.json").read_text())
salt = (fixture["sessionId"] + ":" + fixture["inviteId"]).encode()
prk = hmac.new(salt, bytes.fromhex(fixture["secret"]), hashlib.sha256).digest()
for role, field in (("admission", "admission"), ("host", "hostKey"), ("guest", "guestKey")):
    info = ("veil.signaling.v2:" + role).encode()
    assert hmac.new(prk, info + b"\x01", hashlib.sha256).hexdigest() == fixture[field]
assert hashlib.sha256(fixture["admission"].encode()).hexdigest() == fixture["admissionHash"]
print("PASS: public HKDF protocol fixture")
