
# **Instructions for Using the DNA-RNA Encryption Script**

## **Brief Description**

This script implements a unique encryption scheme by combining AES-256, XOR, and DNA-RNA representation. The encryption process consists of several stages:

1.  **AES-256 Encryption**: Data is encrypted using AES in EAX mode.
2.  **XOR Encryption**: The encrypted result is converted to binary and re-encrypted using XOR with a 512-bit key.
3.  **DNA Encoding**: Binary data is converted into DNA form (A, T, G, C).
4.  **DNA Complementary Pairing**: DNA is complemented for additional security.
5.  **RNA Transcription**: DNA is converted into RNA as the final stage of encryption.

The decryption process performs the reverse operations to retrieve the original data.

----------

## **Requirements**

This script requires the **PyCryptodome** library for AES encryption. Install it using the following command:

```sh
pip install pycryptodome
```

----------

## **Usage Examples**

### **1. Encrypting Text**

```python
from dna_enc import encrypt_text, generate_long_key

aes_key = b"my_secure_aes_key_32_bytes_length"
dna_key = generate_long_key()

plaintext = "Hello, this is a secret message!"

# Encryption
encrypted_rna = encrypt_text(plaintext, aes_key, dna_key)
print("Encrypted RNA:", encrypted_rna)

```

### **2. Decrypting Text**

```python
from dna_enc import decrypt_text

# Decryption
decrypted_text = decrypt_text(encrypted_rna, aes_key, dna_key)
print("Decrypted Text:", decrypted_text)

```

### **3. Encrypting a File**

```python
from dna_enc import encrypt_file

file_path = "data.txt"
encrypt_file(file_path, aes_key, dna_key)

```

### **4. Decrypting a File**

```python
from dna_enc import decrypt_file

encrypted_file = "data.txt.rnaenc"
decrypt_file(encrypted_file, aes_key, dna_key)

```

----------

## **Notes**

-   Ensure the AES key is **32 bytes** long for AES-256.
-   The DNA key must be generated using `generate_long_key()`.
-   Make sure the key used for decryption is the same as the one used for encryption.

With this method, data becomes more secure and difficult to reconstruct without the correct key.
