import plistlib
from base64 import b64decode

import requests

from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair, parse_key, serialize_key
from .signing import add_auth_signature, armour_cert

from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec, rsa

import logging
logger = logging.getLogger("ids")

class IDSIdentity:
    def __init__(self, signing_key: str | None = None, encryption_key: str | None = None, signing_public_key: str | None = None, encryption_public_key: str | None = None):
        if signing_key is not None:
            self.signing_key = signing_key
            self.signing_public_key = serialize_key(parse_key(signing_key).public_key())
        elif signing_public_key is not None:
            self.signing_key = None
            self.signing_public_key = signing_public_key
        else:
            # Generate a new key
            self.signing_key = serialize_key(ec.generate_private_key(ec.SECP256R1()))
            self.signing_public_key = serialize_key(parse_key(self.signing_key).public_key())
        
        if encryption_key is not None:
            self.encryption_key = encryption_key
            self.encryption_public_key = serialize_key(parse_key(encryption_key).public_key())
        elif encryption_public_key is not None:
            self.encryption_key = None
            self.encryption_public_key = encryption_public_key
        else:
            self.encryption_key = serialize_key(rsa.generate_private_key(65537, 1280))
            self.encryption_public_key = serialize_key(parse_key(self.encryption_key).public_key())
        
    def decode(input: bytes) -> 'IDSIdentity':
        input = BytesIO(input)

        assert input.read(5) == b'\x30\x81\xF6\x81\x43' # DER header
        raw_ecdsa = input.read(67)
        assert input.read(3) == b'\x82\x81\xAE' # DER header
        raw_rsa = input.read(174)

        # Parse the RSA key
        raw_rsa = BytesIO(raw_rsa)
        assert raw_rsa.read(2) == b'\x00\xAC' # Not sure what this is
        assert raw_rsa.read(3) == b'\x30\x81\xA9' # Inner DER header
        assert raw_rsa.read(3) == b'\x02\x81\xA1'
        rsa_modulus = raw_rsa.read(161)
        rsa_modulus = int.from_bytes(rsa_modulus, "big")
        assert raw_rsa.read(5) == b'\x02\x03\x01\x00\x01' # Exponent, should always be 65537

        # Parse the EC key
        assert raw_ecdsa[:3] == b'\x00\x41\x04'
        raw_ecdsa = raw_ecdsa[3:]
        ec_x = int.from_bytes(raw_ecdsa[:32], "big")
        ec_y = int.from_bytes(raw_ecdsa[32:], "big")

        ec_key = ec.EllipticCurvePublicNumbers(ec_x, ec_y, ec.SECP256R1())
        ec_key = ec_key.public_key()

        rsa_key = rsa.RSAPublicNumbers(e=65537, n=rsa_modulus)
        rsa_key = rsa_key.public_key()

        return IDSIdentity(signing_public_key=serialize_key(ec_key), encryption_public_key=serialize_key(rsa_key))


    def encode(self) -> bytes:
        output = BytesIO()

        raw_rsa = BytesIO()
        raw_rsa.write(b'\x00\xAC')
        raw_rsa.write(b'\x30\x81\xA9')
        raw_rsa.write(b'\x02\x81\xA1')
        raw_rsa.write(parse_key(self.encryption_public_key).public_numbers().n.to_bytes(161, "big"))
        raw_rsa.write(b'\x02\x03\x01\x00\x01') # Hardcode the exponent

        output.write(b'\x30\x81\xF6\x81\x43')
        output.write(b'\x00\x41\x04')
        output.write(parse_key(self.signing_public_key).public_numbers().x.to_bytes(32, "big"))
        output.write(parse_key(self.signing_public_key).public_numbers().y.to_bytes(32, "big"))

        output.write(b'\x82\x81\xAE')
        output.write(raw_rsa.getvalue())

        return output.getvalue()
        
def register(
    push_token, handles, user_id, auth_key: KeyPair, push_key: KeyPair, identity: IDSIdentity, validation_data
):
    logger.debug(f"Registering IDS identity for {handles}")
    uris = [{"uri": handle} for handle in handles]

    body = {
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        "software-version": "22D68",
        "device-name": "James’s Laptop",
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.4.1,22F82",
        "private-device-data": {
            "ap": "0",
            "d": "717785001.181324",
            "dt": "1",
            "gt": "0",
            "h": "1",
            "ktf": "0",
            "ktv": "70",
            "m": "0",
            "p": "0",
            "pb": "22F82",
            "pn": "macOS",
            "pv": "13.4.1",
            "s": "0",
            "t": "0",
            "u": "E451BD65-51B0-44F3-805A-A92BDD8A5000",
            "v": "1",
        },
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "users": [
                    {
                        "client-data": {
                            'is-c2k-equipment': True,
						    'optionally-receive-typing-indicators': True,
						    'public-message-identity-key': identity.encode(),
						    'public-message-identity-version':2,
                            'show-peer-errors': True,
                            'supports-ack-v1': True,
                            'supports-activity-sharing-v1': True,
                            'supports-audio-messaging-v2': True,
                            "supports-autoloopvideo-v1": True,
                            'supports-be-v1': True,
                            'supports-ca-v1': True,
                            'supports-fsm-v1': True,
                            'supports-fsm-v2': True,
                            'supports-fsm-v3': True,
                            'supports-ii-v1': True,
                            'supports-impact-v1': True,
                            'supports-inline-attachments': True,
                            'supports-keep-receipts': True,
                            "supports-location-sharing": True,
                            'supports-media-v2': True,
                            'supports-photos-extension-v1': True,
                            'supports-st-v1': True,
                            'supports-update-attachments-v1': True,
                        },
                        "uris": uris,
                        "user-id": user_id,
                    }
                ],
            }
        ],
        "software-version": "22F82",
        #"validation-data": b64decode(validation_data),
        "validation-data": b64decode("""AiZPQSUbQiOdgm6ZYJlYH5fmLGsDdgR/D1qiKCvZ37vvAAAB4AcAAAABAAABgDaBPLlH
      8CwoQ1FYxR68/n1h93n8Z6FqL0K2a/TueX89Zebqo/2yGI4uGZ4nnk9dyuN7nxBJlBrg
      7z7OnWywsnWIS1QLzJE1ktOGG7PlBJ+NioIkEfvydNomlkBVPGxQIi/2LT7shBPncP9T
      At6M3fxxQRQhpAeC0J9t6X7Ez5bWbaPwXirRfcVepPx2WZaSOJ8kYRxCPBMFYVlmW9n4
      uK3pn/vefAqbCyOmub7Qw/Jnna4WHcRxqW2/nOPwHa2l1ZeIRH5mQ58PqxMOf0XtIuld
      i8hMlPaEzlkWt1qggUrF5ZO8uj+EgOjR0weDsJm0Ckfcw4tSDIQ7FXQlzseVN4qTcDjs
      3NxklUItmIBqDPt+8GvNIY2hd1BjmFgW5IE8zHNoMOGbm7p7Wf7Flp0W6Rm+9lCmjBSH
      Oh+F8Bf97gtqC+vDjT7wKYC4k/c0S4b0mycCW+P/JQhLvIDRr3+UN25dTUMElirxZd3Q
      Ek82GQWX4y3ld6pDH+omfUlFew4yxwAAAAAAAABPAVDGn6dOi1pJ7VJiAGFhTLzAJZlz
      AAAANgIEktrH8a9tLuzWOyQ9AbVMhWUYlhTFSvLPhnbjdWJEOrmxXbI94Bc4WwH0+3ow
      wl/bf/hCXg==""")
    }

    body = plistlib.dumps(body)
    import gsa

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": user_id,
        "user-agent": "com.apple.invitation-registration [macOS,13.2.1,22D68,MacBookPro18,3]",
    }
    a = gsa.Anisette().generate_headers()
    headers.update(a)
    add_auth_signature(headers, body, "id-register", auth_key, push_key, push_token, 0)

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)
    #print(f'Response code: {r["status"]}')
    logger.debug(f"Recieved response to IDS registration: {r}")
    if "status" in r and r["status"] == 6004:
        raise Exception("Validation data expired!")
    # TODO: Do validation of nested statuses
    if "status" in r and r["status"] != 0:
        raise Exception(f"Failed to register: {r}")
    if not "services" in r:
        raise Exception(f"No services in response: {r}")
    if not "users" in r["services"][0]:
        raise Exception(f"No users in response: {r}")
    if not "cert" in r["services"][0]["users"][0]:
        raise Exception(f"No cert in response: {r}")

    return armour_cert(r["services"][0]["users"][0]["cert"])
