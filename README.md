# CipherNova - Hybrid Encryption & Secure Vault for forensic evidences.
CipherNova is a desktop application that implements real-world hybrid encryption to protect sensitive files and messages. It combines the strengths of asymmetric (RSA) and symmetric (AES) cryptography, along with digital signatures and integrity verification, to provide reliable protection for data stored on local machines.

#### Long-Term Vision: 
CipherNova is designed to evolve into a secure vault for forensic evidence — providing tamper-proof, signed, integrity-verified storage of critical files for investigators, cybersecurity professionals, and privacy-focused individuals.

## 🎯 Key Technical Features

- #### Hybrid Encryption (RSA + AES)
Files and messages are encrypted using AES-256 in CFB mode, with the AES key itself securely encrypted using RSA-2048 and OAEP padding.
- #### Digital Signatures (RSA-PSS)
Encrypted files are signed with the RSA private key using modern PSS padding and SHA-256 hashing, ensuring authenticity and non-repudiation.
- #### HMAC-SHA256 Integrity Check
The plaintext's HMAC is stored and verified upon decryption, providing tamper detection even if encryption remains intact.
- #### Structured Encrypted File Format
CipherNova outputs encrypted files in a structured binary format containing:
```bash 
[Encrypted AES Key] + [IV] + [HMAC] + [Ciphertext] + [Signature]
```

- #### Tkinter-Based GUI
A simple, beginner-friendly desktop interface guides the user through encryption, decryption, and key management.
- #### Password-Protected Key Storage
The RSA private key is securely stored in an encrypted PEM format, requiring a password for decryption during use.

### 🧩 Technical Foundations
CipherNova reflects modern best practices in applied cryptography:
      - RSA-2048 with OAEP: Secure asymmetric key encryption
      - AES-256-CFB: Efficient, strong symmetric encryption
      - HMAC-SHA256: Lightweight, reliable integrity verification
      - RSA-PSS Signatures: Strong, randomized digital signatures to prevent forgery
      - Key Management: User-generated keys, encrypted private key storage

These techniques mirror the foundational principles seen in real-world tools like GPG, encrypted messaging apps, and secure file transfer systems.

### 🧭 Intended Use Cases
Local file and message encryption
Educational tool for understanding applied cryptography
Prototype foundation for future secure storage systems
Ideal for students, cybersecurity learners, and privacy-conscious users

### 🔍 Project Vision: Evolving Into a Secure Evidence Vault
- The broader motivation for CipherNova is to develop a desktop-friendly, tamper-proof Forensic Evidence Vault, aimed at:
- Secure storage of digital evidence (logs, files, documents)
- Tamper detection and signed authenticity proofs
- Usability for field investigators, SOC teams, or ethical hackers
The current release lays the cryptographic foundation for this system, with future improvements planned to fulfill this vision.

### 💻 How to Run

```bash
python gui.py
```
On first run, you will be prompted to set a password for your private key. This password is required for any decryption or signing operations.

### 🧑‍💻 My Key Takeaways
- Building CipherNova has enhanced my technical and practical understanding of:
- Correct hybrid encryption implementation (RSA + AES)
- Secure key management and password protection principles
- Digital signatures and their role in authenticity verification
- Structuring Python projects for modular, reusable code
- Designing accessible GUI applications with Tkinter
- Bridging theoretical cryptography with practical software development

This project helped me understand both the capabilities and limitations of modern encryption techniques, reinforcing the importance of security-by-design thinking.

### 🚧 Limitations & Future Improvements
Currently intended for local use only — no secure file sharing
No key export/import functionality (planned)
GUI aesthetics can be enhanced
Vault system for organized evidence storage (in development)
Advanced key management (e.g., revocation) for production-grade use

### ⚡ Why This Project Stands Out (Compared to Existing Tools)
While many encryption tools exist, CipherNova focuses on:

- ✔ Beginner-friendly, transparent encryption for educational value
- ✔ Honest, properly implemented hybrid encryption — not just AES alone
- ✔ Integrated digital signatures and integrity checks in one tool
- ✔ The foundation for a specialized, secure evidence locker
- ✔ Clean, Python-based code suitable for learning and extension

### 📦 Project Structure
```bash
cipherNova/
├── gui.py               # Main application GUI
├── crypto_utils.py      # Cryptography logic (RSA, AES, HMAC, Signatures)
├── file_utils.py        # File dialogs and basic utilities
├── keys/                # Securely stored keys (generated at runtime)
├── vault/               # [Planned] Encrypted evidence and file storage
├── logs/                # [Optional] Future log storage
└── requirements.txt     # Dependencies
```
### POC:

### ⚒ Requirements
Basic dependencies (Python 3.9+ recommended):
```bash
cryptography
tkinter
```
##### Install with:
``` bash
pip install -r requirements.txt
```
### 🛡 Disclaimer
CipherNova is an educational project intended to demonstrate secure encryption practices in a desktop environment. It is not intended for production use in high-risk environments or as a substitute for audited, professionally maintained encryption solutions.

