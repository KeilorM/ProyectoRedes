from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Generar clave privada de la CA
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Crear certificado CA autofirmado
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Proxy UNA CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UNA Redes"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

# Guardar archivos
with open("ca.key", "wb") as f:
    f.write(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
with open("ca.crt", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("✅ ca.key y ca.crt generados")