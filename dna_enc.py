
import os
import secrets
from Crypto.Cipher import AES

# DNA Encoding Table (Binary → 3 basa DNA)
binary_to_codon = {"00": "ATG", "01": "TAC", "10": "GCT", "11": "CGA"}
codon_to_binary = {v: k for k, v in binary_to_codon.items()}

# Complementary DNA Pair
complementary_dna = {"A": "T", "T": "A", "C": "G", "G": "C"}

# DNA → RNA Transcription Table
dna_to_rna = {"A": "U", "T": "A", "C": "G", "G": "C"}

# RNA Codon → Amino Acid Translation Table
rna_to_protein = {
    "AUG": "M", "TAC": "Y", "GCU": "A", "CGA": "R",
    "UAA": "*", "UAG": "*", "UGA": "*"
}

def generate_long_key():
    """Generate 512-bit key for XOR encryption."""
    return secrets.token_hex(64)  # 512-bit key (64 bytes)

def xor_encrypt(binary_data, key):
    """Apply XOR encryption using a long 512-bit key."""
    key_bin = ''.join(format(int(key[i:i+2], 16), '08b') for i in range(0, len(key), 2))
    key_bin = (key_bin * (len(binary_data) // len(key_bin) + (1 if len(binary_data) % len(key_bin) else 0)))[:len(binary_data)]
    return ''.join(str(int(b) ^ int(k)) for b, k in zip(binary_data, key_bin))

def aes_encrypt(data, key):
    """Encrypt data using AES-256 (EAX mode)."""
    key = key[:32] if len(key) >= 32 else os.urandom(32)  # Ensure key is 32 bytes
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def aes_decrypt(encrypted_data, key):
    """Decrypt AES-256 encrypted data."""
    key = key[:32] if len(key) >= 32 else os.urandom(32)  # Ensure key is 32 bytes
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def transcribe_dna_to_rna(dna_sequence):
    """Convert DNA sequence to RNA sequence."""
    return ''.join(dna_to_rna[base] for base in dna_sequence)

def translate_rna_to_protein(rna_sequence):
    """Convert RNA sequence to protein sequence (simplified)."""
    protein_sequence = ''
    for i in range(0, len(rna_sequence), 3):
        codon = rna_sequence[i:i+3]
        protein_sequence += rna_to_protein.get(codon, "?")  # ? untuk kodon tidak dikenal
    return protein_sequence

def encrypt_data(data, aes_key, dna_key):
    """Encrypt binary data using AES-256, DNA encoding, and RNA translation."""
    encrypted_data = aes_encrypt(data, aes_key)
    binary_data = ''.join(format(byte, '08b') for byte in encrypted_data)  # Convert to binary
    xor_binary = xor_encrypt(binary_data, dna_key)  # XOR encryption

    dna_sequence = ''.join(binary_to_codon[xor_binary[i:i+2]] for i in range(0, len(xor_binary), 2))
    complementary_sequence = ''.join(complementary_dna[base] for base in dna_sequence)  # Complementary DNA
    rna_sequence = transcribe_dna_to_rna(complementary_sequence)  # Transkripsi ke RNA

    return rna_sequence

def decrypt_data(rna_sequence, aes_key, dna_key):
    """Decrypt RNA-encoded data back to its original binary form."""
    complementary_sequence = ''.join(k for base in rna_sequence for k, v in dna_to_rna.items() if v == base)
    dna_sequence = ''.join(complementary_dna[base] for base in complementary_sequence)
    xor_binary = ''.join(codon_to_binary.get(dna_sequence[i:i+3], "") for i in range(0, len(dna_sequence), 3))

    binary_data = xor_encrypt(xor_binary, dna_key)
    decrypted_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

    return aes_decrypt(decrypted_data, aes_key)

def encrypt_file(file_path, aes_key, dna_key):
    """Encrypt a file and save the RNA-encoded output."""
    with open(file_path, "rb") as f:
        file_data = f.read()

    encrypted_rna = encrypt_data(file_data, aes_key, dna_key)

    encrypted_file = file_path + ".rnaenc"
    with open(encrypted_file, "w") as f:
        f.write(encrypted_rna)

    print(f"File encrypted: {encrypted_file}")

def decrypt_file(encrypted_file, aes_key, dna_key):
    """Decrypt an RNA-encoded file back to its original form."""
    with open(encrypted_file, "r") as f:
        rna_sequence = f.read()

    original_data = decrypt_data(rna_sequence, aes_key, dna_key)

    output_file = encrypted_file.replace(".rnaenc", "")
    with open(output_file, "wb") as f:
        f.write(original_data)

    print(f"File decrypted: {output_file}")

def encrypt_text(plaintext, aes_key, dna_key):
    """Encrypt plaintext into RNA sequence."""
    encrypted_rna = encrypt_data(plaintext.encode(), aes_key, dna_key)
    return encrypted_rna

def decrypt_text(rna_sequence, aes_key, dna_key):
    """Decrypt RNA sequence back to plaintext."""
    decrypted_data = decrypt_data(rna_sequence, aes_key, dna_key)
    return decrypted_data.decode()
