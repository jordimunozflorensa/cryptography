from sympy import isprime, mod_inverse
from ecpy.curves import Curve, Point
import hashlib
from asn1crypto.core import Sequence

print("a) Comprobad que el número de puntos (orden) de la curva usada en el certificado es primo.")
print("namedCurve: 1.2.840.10045.3.1.7 (secp256r1)")

# Genera la curva secp256r1 y obtiene el orden
curve = Curve.get_curve('secp256r1')
n = curve.order

if (isprime(n)):
	print("El orden de la curva es primo.\n")
else:
	print("El orden de la curva no es primo.\n")

# ----------------------------------------------------------------------------------------------

print("b) Comprobad que la clave pública P de www.wikipedia.org es realmente un punto de la curva.")
print("subjectPublicKey: 0429fef70279c982b52644e9c9bf063ecf49a2d2eafe3154e353dd7bef217923a820d71e3974bf5c0f856ba16c518548c2b81110a8c32de52208beab40cf3c440e")

with open("./subjectPublicKey.hex", "r") as f:
    subjectPublicKey_hex = f.read()
subjectPublicKey_bytes = bytes.fromhex(subjectPublicKey_hex)

# Decodifica la clave pública y verifica si está en la curva
P_wiki = curve.decode_point(subjectPublicKey_bytes)
if (curve.is_on_curve(P_wiki)):
	print("La clave pública P está en la curva.\n")
else:
	print("La clave pública P no está en la curva.\n")

# ----------------------------------------------------------------------------------------------

print("c) Calculad el orden del punto P.")
print(f"El orden del punto P es: {n}\n")

# ----------------------------------------------------------------------------------------------

print("d) Comprobad que la firma ECDSA es válida.")


with open("./mensaje.hex", "r") as f:
	mensaje_hex = f.read()
mensaje = bytes.fromhex(mensaje_hex)

# Calcula el hash SHA-256 del mensaje
print("Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)")
mensaje256 = hashlib.sha256(mensaje).digest()
print(f"Hash SHA-256 del mensaje (hex): {mensaje256.hex()}")

# Preambulo
preambulo = (b'\x20'*64) + b'TLS 1.3, server CertificateVerify' + b'\x00'

concat_data = preambulo + mensaje256

# Hash concatenación
m = hashlib.sha256(concat_data).digest()
print(f"Mensaje firmado (hash SHA-256 de preambulo + mensaje256) (hex): {m.hex()}")

# Firma
print("Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)")
with open("./firma.hex", "r") as f:
	firma_hex = f.read()
firma = bytes.fromhex(firma_hex)

# Firma en formato ASN.1
asn1_signature = Sequence.load(firma)
f1 = asn1_signature[0].native
f2 = asn1_signature[1].native
print(f"f1: {hex(f1)}")
print(f"f2: {hex(f2)}")

# Verifica la firma
Qx = int.from_bytes(subjectPublicKey_bytes[1:33], byteorder='big')
Qy = int.from_bytes(subjectPublicKey_bytes[33:65], byteorder='big')

public_key = Point(Qx, Qy, curve)

f2i = mod_inverse(f2, n)
f2i = int(f2i)  # inverso modular como entero
w1 = (int.from_bytes(m, byteorder='big') * f2i) % n
w2 = (f1 * f2i) % n

P = curve.generator
E = (w1 * P) + (w2 * public_key)

print(f"E.x vale {E.x % n}")
print(f"f1 vale {f1 % n}")

# Verificación
if (E.x % n) == (f1 % n):
	print("La firma es válida.")
else:
	print("La firma no es válida.")
