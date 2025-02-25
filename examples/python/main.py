import textwrap
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import base64
import est.client

def ConvertPkcs7ToPem(newPkcs7):
    newPem = ""
    if isinstance(newPkcs7, bytes):
        in_bytes = newPkcs7
    else:
        in_bytes = str.encode(newPkcs7)

    # parse from der (binary) format
    newCerts = pkcs7.load_der_pkcs7_certificates(in_bytes)
    # newCerts = pkcs7.load_pem_pkcs7_certificates(in_bytes)
    for eachCert in newCerts:
        newPem += eachCert.subject.rfc4514_string() + "\n"
        newPem += eachCert.issuer.rfc4514_string() + "\n"
        newPem += eachCert.public_bytes(serialization.Encoding.PEM).decode()
    return newPem

host = 'localhost'
port = 8443
implicit_trust_anchor_cert_path = 'server.pem'
implicit_trust_anchor_cert_path = False

client = est.client.Client(host, port, implicit_trust_anchor_cert_path)

# Get CSR attributes from EST server as an OrderedDict.
# csr_attrs = client.csrattrs()

# Get EST server CA certs.
# ca_certs = client.cacerts()

common_name = 'golang-est-client001'

username = common_name
password = ''
client.set_basic_auth(username, password)

# Create CSR and get private key used to sign the CSR.
country = 'US'
state = 'Massachusetts'
city = 'Boston'
organization = 'Cisco Systems'
organizational_unit = 'ENG'
email_address = 'test@cisco.com'

priv, csr = client.create_csr(common_name, country, state, city,
                                     organization, organizational_unit,
                                     email_address)

# Enroll: get cert signed by the EST server.
csr = csr.replace(b"-----BEGIN CERTIFICATE REQUEST-----\n", b"")
csr = csr.replace(b"-----END CERTIFICATE REQUEST-----\n", b"")
csr = csr.replace(b"\n", b"")
client_cert = client.simpleenroll(csr)

# wrapped_cert = '\n'.join(textwrap.wrap(client_cert, width=64))
# pem_cert = "-----BEGIN CERTIFICATE-----\n" + wrapped_cert + "\n" + "-----END CERTIFICATE-----\n"
# cert = x509.load_pem_x509_certificate(str.encode(pem_cert))

client_cert_pem = ConvertPkcs7ToPem(client_cert)


# Re-Enroll: Renew cert.  The previous cert/key can be passed for auth if needed.
#client_cert = client.simplereenroll(csr)
