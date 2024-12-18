from Crypto.PublicKey import RSA
import sympy
import math
from glob import glob   
import subprocess
# import re

name='yiqi.zheng'

file_name = "RSA_RW-20241126/"+name+"_pubkeyRSA_RW.pem"

###################################### PARTE 1 ######################################

## Read the public key from the file

# result = subprocess.run(
#     ["openssl", "rsa", "-in", file_name, "-pubin", "-text", "-noout"],
#     capture_output=True,
#     text=True
# )

# output = result.stdout

# modulus_match = re.search(r'Modulus:\s+((?:\s*[0-9a-f]{2}:)+[0-9a-f]{2})', output, re.IGNORECASE)
# exponent_match = re.search(r'Exponent:\s+(\d+)', output)

# if modulus_match and exponent_match:
#     modulus_hex = modulus_match.group(1).replace(':', '').replace('\n', '').replace(' ', '')
#     modulus = int(modulus_hex, 16)
#     exponent = int(exponent_match.group(1))

#     print(f"Modulus: {modulus}")
#     print(f"Exponent: {exponent}")
# else:
#     print("Failed to extract modulus or exponent")

with open(file_name, 'r') as file:
    file_content = file.read()
    
pubkey = RSA.importKey(file_content)
modulus = pubkey.n
public_exponent = pubkey.e

print(f"Modulus: {modulus}")
print(f"Public exponent: {public_exponent}")

## Find the private key

p , q = 0, 0

for filename in glob('RSA_RW-20241126/*pubkeyRSA_RW*.pem'):
    f = open(filename)
    if name in f.name:
        continue
    key2 = f.read()
    pubkey2 = RSA.importKey(key2)
    modulusB = pubkey2.n
    gdc = math.gcd(modulus,modulusB)
    if gdc != 1:
        if not p:
            p = gdc
        else:
            q = gdc
            break
phi = (p-1)*(q-1)
private_exponent = sympy.mod_inverse(public_exponent,phi)

privateA = RSA.construct((modulus, public_exponent, int(private_exponent)))

outputA = open("rw_rsa/"+name+"_privatekey_rw.pem", 'wb')
outputA.write(privateA.exportKey('PEM'))
outputA.close()

# Decrypt the RSA encrypted file using the private key
subprocess.run([
    "openssl", "pkeyutl", "-decrypt", 
    "-inkey", "rw_rsa/"+name+"_privatekey_rw.pem", 
    "-in", "RSA_RW-20241126/"+name+"_RSA_RW.enc", 
    "-out", "rw_rsa/"+name+"clave_AES.key"
])

# Decrypt the AES encrypted file using the decrypted key
subprocess.run([
    "openssl", "enc", "-d", "-aes-128-cbc", "-pbkdf2", 
    "-kfile", "rw_rsa/"+name+"clave_AES.key", 
    "-in", "RSA_RW-20241126/"+name+"_AES_RW.enc", 
    "-out", "rw_rsa/"+name+"_fichero_descifrado"
])
