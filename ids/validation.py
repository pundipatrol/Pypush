import requests
import plistlib
import base64

def parse_cert_chain(chain: bytes):
    version = chain[0]
    count = chain[1]
    seek = 2
    certs = []
    for _ in range(count):
        length = int.from_bytes(chain[seek:seek+4], "big")
        seek += 4
        cert = chain[seek:seek+length]
        seek += length
        certs.append(cert)
    return certs

def serialize_cert_chain(certs: list[bytes]):
    chain = bytearray()
    chain.append(0x01)
    chain.append(len(certs))
    for cert in certs:
        chain.extend(len(cert).to_bytes(4, "big"))
        chain.extend(cert)
    return bytes(chain)

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def load_cert_chain(chain: bytes):
    certs = parse_cert_chain(chain)
    out = []
    for cert in certs:
        cert = x509.load_der_x509_certificate(cert)
        print(f"Found cert: {cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
        #print(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip())
        out.append(cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip())
    return out

def create_cert_chain(certs: list[str]):
    # Load the certs and convert them to DER
    certs = [x509.load_pem_x509_certificate(cert.encode()) for cert in certs]
    certs = [cert.public_bytes(serialization.Encoding.DER) for cert in certs]
    # Create the chain
    return serialize_cert_chain(certs)


def test():
    resp = requests.get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
    #print(resp.content)
    resp = plistlib.loads(resp.content)
    cert = resp['cert']
    dec = load_cert_chain(cert)
    print(dec[1])
    print(create_cert_chain([dec[1]]).hex())


    #print(parse_cert_chain(cert))
    #print(base64.b64decode(cert))

if __name__ == "__main__":
    test()