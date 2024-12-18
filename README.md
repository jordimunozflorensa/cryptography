# Cryptography Implementations

Welcome to the **Cryptography Implementations** repository! This project contains implementations of various cryptographic algorithms and concepts, including **AES (Advanced Encryption Standard)**, **RSA (Rivest–Shamir–Adleman)**, and a basic **Blockchain**.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [AES Encryption/Decryption](#aes-encryptiondecryption)
  - [RSA Encryption/Decryption](#rsa-encryptiondecryption)
  - [Blockchain Implementation](#blockchain-implementation)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This repository demonstrates the practical use of modern cryptographic algorithms and technologies. It includes implementations of:

- **AES:** A symmetric encryption algorithm widely used for securing sensitive data.
- **RSA:** An asymmetric encryption algorithm used for secure data transmission and digital signatures.
- **Blockchain:** A simplified implementation to understand the underlying mechanics of decentralized ledger technology.

## Features

- Well-documented and modular codebase.
- Examples for encrypting and decrypting data using AES and RSA.
- A basic blockchain implementation that includes features like block validation and proof-of-work.
- Beginner-friendly with step-by-step instructions to get started.

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Required libraries: `pycryptodome` (for cryptographic operations), `hashlib` (for hashing), and `json` (for blockchain serialization).

Install the required libraries using pip:

```bash
pip install pycryptodome
```

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cryptography-implementations.git
   cd cryptography-implementations
   ```
2. Ensure you have all dependencies installed.

---

## Usage

### AES Encryption/Decryption

1. Navigate to the `aes` directory.
2. Run the script and follow the prompts to encrypt or decrypt a message:
   ```bash
   python aes.py
   ```
3. Example:
   - Input plaintext: `Hello, World!`
   - Output ciphertext: `b'\x89\x90...\x3c'`

### RSA Encryption/Decryption

1. Navigate to the `rsa` directory.
2. Generate RSA keys and use them for encryption or decryption:
   ```bash
   python rsa.py
   ```
3. Example:
   - Generate a key pair.
   - Encrypt: `plaintext -> ciphertext`
   - Decrypt: `ciphertext -> plaintext`

### Blockchain Implementation

1. Navigate to the `blockchain` directory.
2. Run the blockchain simulation:
   ```bash
   python blockchain.py
   ```
3. Features include:
   - Adding new transactions.
   - Mining new blocks.
   - Displaying the blockchain state.

---

## Project Structure

```
cryptography-implementations/
|
├── aes/
│   ├── aes.py         # AES encryption and decryption implementation
│   └── 01-Secreta.pdf # pdf with the explanaition
│   └── aes_class.py   # cotains the aes class
│   └── cuerpo_finito.py   # cotains the galois field implementation
│   └── others         # files to check 
|
├── rsa/
│   ├── 02-BlockChain.pdf    # pdf with the explanaition
│   └── rsa_jordi_yiqi       # folder with the implementation done to solve the RSA part from the pdf
│   └── RSA_pseudo-20241126  # folder with the files needed for the pseudo part
│   └── RSA_RW-20241126      # folder with the files for the raw part
|
├── blockchain/
│   ├── 02-BlockChain.pdf         # pdf with the explanaition
│   └── testear_blockchain.ipynb  # file to test the blockchain   
│   └── others                    # files to test and folder to test
|
├── tests/             # Unit tests for AES, RSA, and Blockchain
└── README.md          # Project documentation
```

---

## Contributing

We welcome contributions from the community! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with detailed explanations of your changes.

Please ensure your code adheres to the repository’s coding standards and includes relevant documentation.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

Happy coding! If you find this project helpful, feel free to give it a star and share your feedback!

