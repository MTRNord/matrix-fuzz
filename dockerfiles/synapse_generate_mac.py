import hashlib
import hmac
import os


def generate_mac(nonce, user, password, admin=False, user_type=None):
    mac = hmac.new(
        key=b"sahZae3yahjaequ8boh2cae5uo5eiciede2hoa9eew8mai1oy4iiChietheequ9U",
        digestmod=hashlib.sha1,
    )

    mac.update(nonce.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.encode('utf8'))
    mac.update(b"\x00")
    mac.update(password.encode('utf8'))
    mac.update(b"\x00")
    mac.update(b"admin" if admin else b"notadmin")
    if user_type:
        mac.update(b"\x00")
        mac.update(user_type.encode('utf8'))

    return mac.hexdigest()


hmac = generate_mac(os.environ['NONCE'], "fuzzer",
                    "Chu8chool0dooqueiwo0lohviegho6ieveuNg3Ohcio2aekaiw0ioF6waifo8eep")
print(f"::set-output name=hmac::{hmac}")
