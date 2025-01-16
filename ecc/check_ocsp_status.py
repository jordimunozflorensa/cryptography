import subprocess

def check_ocsp_status(cert_file, issuer_cert_file, ocsp_url):
    command = [
        "openssl", "ocsp",
        "-issuer", issuer_cert_file,
        "-cert", cert_file,
        "-url", ocsp_url,
        "-text"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    cert_file = "server_cert.pem"
    issuer_cert_file = "issuer_cert.pem"
    ocsp_url = "http://GEANT.ocsp.sectigo.com"
    
    status = check_ocsp_status(cert_file, issuer_cert_file, ocsp_url)
    print(status)