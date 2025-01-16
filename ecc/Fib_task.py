print("a) Obtened el periodo de validez del certificado y la clave pública (módulo y exponente, en base 10 del web de la FIB. ¿Cuántos digitos tiene el módulo?")
validity_not_before = "utcTime: 2024-12-05 00:00:00 (UTC)"
validity_not_after = "utcTime: 2025-12-05 23:59:59 (UTC)"
print(f"Periodo de validez del certificado: {validity_not_before} - {validity_not_after}")
subjectPublicKey = "3082018a0282018100e5e03b19b9d56fb72b7263a095fbcdd5008eeab3877162dd396f83eb3cfca94a7654d43a6475efde5f475ebaeb1915c6cf91bed263aafa170a2d1e27e6d9014ca4f3f906b6474723253a6a0dd2ead2f09d56d399d4bcb4f30c9e14f2603172ec0ac3b932f24198a5aaf05b41198eff17a76f813b7f9df0952dcb114f231707ac4f39d29646887a6a686206ed31d5561cf78b2b3a43912ee39fbd3dbd02e8ca3b358ab30eb03a33db14dfc8376d29623bcb4f2aef23976bbc30846e74894fcf04e8ed34a9209b787ce00d912b30bff174aeb1bfb94bfe14567c98e3c6f173e3645162870a2a65f9228069f985870579bbfa714b42327ce946cf3e319727594c4dc0ac1b658d5a8501d7975205976e19795a6194553007c516f018acb6b177249b92ff4a0aa49717bee0c5fab32c1acb9cd24e024fbecaa3951bf357dda5736af53e3faaafdeaa3b92a3e42b9a9a2cc4a59c61d89bd98c910df57a2809b104f7afb9eecca705948cea0d7539e90033f67e06a7db62e85185041dcda8d2063f839b0203010001"
print(f"Clave pública (hex): {subjectPublicKey}")
modulus_hex = "00e5e03b19b9d56fb72b7263a095fbcdd5008eeab3877162dd396f83eb3cfca94a7654d43a6475efde5f475ebaeb1915c6cf91bed263aafa170a2d1e27e6d9014ca4f3f906b6474723253a6a0dd2ead2f09d56d399d4bcb4f30c9e14f2603172ec0ac3b932f24198a5aaf05b41198eff17a76f813b7f9df0952dcb114f231707ac4f39d29646887a6a686206ed31d5561cf78b2b3a43912ee39fbd3dbd02e8ca3b358ab30eb03a33db14dfc8376d29623bcb4f2aef23976bbc30846e74894fcf04e8ed34a9209b787ce00d912b30bff174aeb1bfb94bfe14567c98e3c6f173e3645162870a2a65f9228069f985870579bbfa714b42327ce946cf3e319727594c4dc0ac1b658d5a8501d7975205976e19795a6194553007c516f018acb6b177249b92ff4a0aa49717bee0c5fab32c1acb9cd24e024fbecaa3951bf357dda5736af53e3faaafdeaa3b92a3e42b9a9a2cc4a59c61d89bd98c910df57a2809b104f7afb9eecca705948cea0d7539e90033f67e06a7db62e85185041dcda8d2063f839b"
modulus_decimal = int(modulus_hex, 16)
print("Número de dígitos del módulo:", len(str(modulus_decimal)), "\n")
publicExponent = 65537  

print("b) En el certificado encontraréis un enlace a la política de certificados (CPS) de la autoridad certificadora firmante. ¿Qué tipo de claves públicas y tamaños admite?")
print("Esta es la página a visitar: https://www.sectigo.com/uploads/files/Sectigo_WebPKI_CP_v1_3_4.pdf")
print("En la página 47 apartado 6.1.5. Key sizes, podemos encontrar que habla de: RSA PKCS #1, RSASSA-PSS, DSA, y ECDSA")
print("Certificados que expiran before December 31, 2030 SHOULD contain subject Public Keys of at least 2048 bits for RSA/DSA, at least 256 bits for elliptic curve")
print("Certificados que expiran after December 31, 2030 SHOULD contain subject Public Keys of at least 3072 bits for RSA/DSA, at least 256 bits for elliptic curve\n")

print("c) En el certificado encontraréis un enlace un punto de distribución de la CRL de la autoridad certificadora. ¿Cuántos certificados revocados contiene la CRL?")
print("uniformResourceIdentifier: http://GEANT.crl.sectigo.com/GEANTOVRSACA4.crl")
print("Ejecutamos el comando: openssl crl -in GEANTOVRSACA4.crl -text -noout | grep -c \"Serial Number\"")
print("El número de certificados revocados es: 26074\n")

print("d) En el certificado encontraréis la dirección OCSP (Online Certificate Status Protocol) a la que se puede preguntar por el estatus del certificado. ¿Cuál es el estatus del certificado y hasta cuándo es válido dicho estatus?")
print("uniformResourceIdentifier: http://GEANT.ocsp.sectigo.com")
print("Ejecutamos el comando: python3 check_ocsp_status.py\n")
print("El estatus del certificado es good y es válido hasta Dec 28 04:31:36 2024 GMT\n")