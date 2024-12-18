from Crypto.PublicKey import RSA
import sympy
import math
from glob import glob   
import subprocess
import re

name='jordi.munoz.florensa'

file_name = "RSA_pseudo-20241126/"+name+"_pubkeyRSA_pseudo.pem"

with open(file_name, 'r') as file:
    file_content = file.read()
    
pubkey = RSA.importKey(file_content)
modulus = pubkey.n
public_exponent = pubkey.e

print(f"Modulus: {modulus}")
print(f"Public exponent: {public_exponent}")


b = 512

offset = -1

while offset < 5:
    offset += 1

    high = (modulus >> b*3) - offset
    mid = (modulus & ((2**(2*b)-1) << b)) >> b
    low = modulus & (2**b-1)

    producte = (high << b) | low
    suma = math.isqrt(mid - (low << b | high) + 2*producte + (offset << 2*b))


    d = suma**2 - 4*producte
    if (d < 0): 
        continue
    r = (suma + math.isqrt(d))//2
    s = (suma - math.isqrt(d))//2

    p = (r << b) | s
    q = (s << b) | r
    if (p*q == modulus):
        break


phi = (p-1)*(q-1)
private_exponent = sympy.mod_inverse(public_exponent,phi)

privateA = RSA.construct((modulus, public_exponent, int(private_exponent)))

outputA = open("pseudo_rsa/"+name+"_privatekey_rw.pem", 'wb')
outputA.write(privateA.exportKey('PEM'))
outputA.close()


# Decrypt the RSA encrypted file using the private key
subprocess.run([
    "openssl", "pkeyutl", "-decrypt", 
    "-inkey", "pseudo_rsa/"+name+"_privatekey_rw.pem", 
    "-in", "RSA_pseudo-20241126/"+name+"_RSA_pseudo.enc",
    "-out", "pseudo_rsa/"+name+"clave_AES.key"
])

# Decrypt the AES encrypted file using the decrypted key
subprocess.run([
    "openssl", "enc", "-d", "-aes-128-cbc", "-pbkdf2", 
    "-kfile", "pseudo_rsa/"+name+"clave_AES.key",
    "-in", "RSA_pseudo-20241126/"+name+"_AES_pseudo.enc",
    "-out", "pseudo_rsa/"+name+"fichero_descifrado"
])