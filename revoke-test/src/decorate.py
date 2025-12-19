import base64
import json
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ENTRUST_SUCKS = ["https://entrustrootcertificationauthorityec1.sectigo.com:444"]


def dissect(url):
    if url in ENTRUST_SUCKS:
        return dict(error = "entrust cannot run a website")

    print(f"URL {url}")
    try:
        out = subprocess.check_output(
            ["curl", "-k", url, "-w", "%{certs}", "-o", "/dev/null", "-s"]
        )
    except subprocess.CalledProcessError as e:
        return dict(error=str(e))

    certs = x509.load_pem_x509_certificates(out)

    if len(certs) < 2:
        return dict(error="no issuer")
    end_entity, issuer = certs[:2]  # sketchy punt

    object = {}
    object["end_entity_cert"] = base64.b64encode(
        end_entity.public_bytes(Encoding.DER)
    ).decode("utf-8")
    object["issuer_cert"] = base64.b64encode(issuer.public_bytes(Encoding.DER)).decode(
        "utf-8"
    )
    serial = end_entity.serial_number
    object["serial"] = base64.b64encode(
        serial.to_bytes((serial.bit_length() + 7) // 8, byteorder="big")
    ).decode("utf-8")
    spki = issuer.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    h = hashes.Hash(hashes.SHA256())
    h.update(spki)
    object["issuer_spki_sha256"] = base64.b64encode(h.finalize()).decode("utf-8")
    object["scts"] = []

    try:
        scts = end_entity.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
    except x509.extensions.ExtensionNotFound:
        return dict(error="missing from ct")

    # print(scts.value)
    for item in scts.value:
        object["scts"].append(
            dict(
                log_id=base64.b64encode(item.log_id).decode("utf-8"),
                timestamp=int(item.timestamp.timestamp() * 1000),
            )
        )

    return dict(detail=object)


if __name__ == "__main__":
    out = {}
    sites = json.load(open("plain.json"))
    for site in sites["sites"]:
        site.update(dissect(site["test_website_revoked"]))
        json.dump(sites, open("decorated.json", "w"), indent=4)
