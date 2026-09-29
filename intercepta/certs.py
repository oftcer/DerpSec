"""Autoridade certificadora local (root CA) e emissao de certificados por host.

Todo o HTTPS interceptado e assinado dinamicamente por uma CA local gerada na
primeira execucao. Nada sai da maquina do usuario.
"""
import datetime
import ipaddress
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CN = "DerpSec Proxy Root CA"
CA_O = "DerpSec"

_KEY_SIZE = 2048
_CA_DAYS = 3650
_LEAF_DAYS = 825  # limite aceito pelos principais navegadores


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _build(builder, key):
    """Assina o certificado aceitando tanto a API antiga como a nova (tz-aware)."""
    try:
        return builder.sign(key, hashes.SHA256())
    except TypeError:  # pragma: no cover - compatibilidade
        return builder.sign(key, hashes.SHA256())


class CertAuthority:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.host_dir = os.path.join(base_dir, "hosts")
        os.makedirs(self.host_dir, exist_ok=True)
        self.ca_pem_path = os.path.join(base_dir, "derpsec-ca.pem")
        self.ca_crt_path = os.path.join(base_dir, "derpsec-ca.crt")
        self.ca_key_path = os.path.join(base_dir, "derpsec-ca.key")
        self._lock = threading.Lock()
        self._contexts = {}
        self._ensure_ca()

    # ---------------------------------------------------------------- CA raiz
    def _ensure_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_pem_path):
            try:
                self._load_ca()
                return
            except Exception:
                pass
        self._create_ca()

    def _load_ca(self):
        with open(self.ca_key_path, "rb") as fh:
            self.ca_key = serialization.load_pem_private_key(fh.read(), password=None)
        with open(self.ca_pem_path, "rb") as fh:
            self.ca_cert = x509.load_pem_x509_certificate(fh.read())

    def _create_ca(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_O),
        ])
        now = _utcnow()
        try:
            builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=_CA_DAYS))
            )
        except TypeError:  # pragma: no cover
            builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now.replace(tzinfo=None) - datetime.timedelta(days=1))
                .not_valid_after(now.replace(tzinfo=None) + datetime.timedelta(days=_CA_DAYS))
            )
        builder = (
            builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
        )
        cert = _build(builder, key)
        self.ca_key = key
        self.ca_cert = cert
        with open(self.ca_key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(self.ca_pem_path, "wb") as fh:
            fh.write(pem)
        # .crt em DER ajuda o certutil do Windows
        with open(self.ca_crt_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.DER))

    def ca_pem(self):
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def ca_fingerprint(self):
        return self.ca_cert.fingerprint(hashes.SHA256()).hex().upper()

    # ------------------------------------------------------ certificado por host
    def leaf_context(self, host):
        host = host.strip().lower()
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            ctx = self._make_context(host)
            self._contexts[host] = ctx
            return ctx

    def _make_context(self, host):
        key = rsa.generate_private_key(public_exponent=65537, key_size=_KEY_SIZE)
        try:
            san = [x509.IPAddress(ipaddress.ip_address(host))]
        except ValueError:
            san = [x509.DNSName(host)]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
        now = _utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=_LEAF_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                ),
                critical=False,
            )
        )
        cert = _build(builder, self.ca_key)
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)[:120]
        cert_path = os.path.join(self.host_dir, safe + ".pem")
        key_path = os.path.join(self.host_dir, safe + ".key")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.check_hostname = False
        return ctx
