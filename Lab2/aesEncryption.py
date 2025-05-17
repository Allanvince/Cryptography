from Crypto.Cipher import AES
import binascii

def hex_to_bytes(hex_str):
    """Convert a hex string to bytes."""
    return binascii.unhexlify(hex_str)

def bytes_to_hex(data):
    """Convert bytes to a hex string."""
    return binascii.hexlify(data).decode('utf-8')

def pkcs5_pad(data):
    """Apply PKCS5 padding to the data."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs5_unpad(data):
    """Remove PKCS5 padding from the data."""
    pad_len = data[-1]
    return data[:-pad_len]

def aes_cbc_decrypt(key, ciphertext):
    """
    Decrypt using AES in CBC mode.
    
    Args:
        key: Hex-encoded AES key (16 bytes)
        ciphertext: Hex-encoded ciphertext with IV prepended
        
    Returns:
        The decrypted plaintext as a string
    """
    # Convert hex to bytes
    key_bytes = hex_to_bytes(key)
    ciphertext_bytes = hex_to_bytes(ciphertext)
    
    # Extract IV (first 16 bytes)
    iv = ciphertext_bytes[:16]
    ciphertext_bytes = ciphertext_bytes[16:]
    
    # Create AES cipher in ECB mode (we'll implement CBC manually)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    # Initialize variables
    plaintext = b""
    prev_block = iv
    
    # Process each block
    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i+16]
        # Decrypt block
        decrypted_block = cipher.decrypt(block)
        # XOR with previous ciphertext block (or IV for first block)
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
        plaintext += plaintext_block
        # Current ciphertext block becomes the "previous" for the next iteration
        prev_block = block
    
    # Remove padding
    plaintext = pkcs5_unpad(plaintext)
    
    # Convert to string
    return plaintext.decode('utf-8')

def aes_ctr_decrypt(key, ciphertext):
    """
    Decrypt using AES in CTR mode.
    
    Args:
        key: Hex-encoded AES key (16 bytes)
        ciphertext: Hex-encoded ciphertext with IV (counter) prepended
        
    Returns:
        The decrypted plaintext as a string
    """
    # Convert hex to bytes
    key_bytes = hex_to_bytes(key)
    ciphertext_bytes = hex_to_bytes(ciphertext)
    
    # Extract IV/counter (first 16 bytes)
    counter = ciphertext_bytes[:16]
    ciphertext_bytes = ciphertext_bytes[16:]
    
    # Create AES cipher in ECB mode (we'll implement CTR manually)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    # Initialize plaintext
    plaintext = b""
    
    # Process each block
    for i in range(0, len(ciphertext_bytes), 16):
        # Get current block (might be less than 16 bytes for the last block)
        block = ciphertext_bytes[i:i+16]
        
        # Encrypt the counter
        encrypted_counter = cipher.encrypt(counter)
        
        # XOR with ciphertext block
        plaintext_block = bytes(x ^ y for x, y in zip(encrypted_counter[:len(block)], block))
        plaintext += plaintext_block
        
        # Increment counter (treating it as a 16-byte big-endian integer)
        # Start from the least significant byte (end) and propagate carry
        counter_int = int.from_bytes(counter, byteorder='big')
        counter_int += 1
        counter = counter_int.to_bytes(16, byteorder='big')
    
    # CTR mode doesn't need padding removal, return the plaintext directly
    return plaintext.decode('utf-8')

# Test cases
def solve_all_problems():
    # Problem 1: CBC
    cbc_key_1 = "140b41b22a29beb4061bda66b6747e14"
    cbc_ciphertext_1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    plaintext_1 = aes_cbc_decrypt(cbc_key_1, cbc_ciphertext_1)
    print(f"CBC Plaintext 1: {plaintext_1}")
    
    # Problem 2: CBC
    cbc_key_2 = "140b41b22a29beb4061bda66b6747e14"
    cbc_ciphertext_2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    plaintext_2 = aes_cbc_decrypt(cbc_key_2, cbc_ciphertext_2)
    print(f"CBC Plaintext 2: {plaintext_2}")
    
    # Problem 3: CTR
    ctr_key_1 = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ciphertext_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    plaintext_3 = aes_ctr_decrypt(ctr_key_1, ctr_ciphertext_1)
    print(f"CTR Plaintext 1: {plaintext_3}")
    
    # Problem 4: CTR
    ctr_key_2 = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ciphertext_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    plaintext_4 = aes_ctr_decrypt(ctr_key_2, ctr_ciphertext_2)
    print(f"CTR Plaintext 2: {plaintext_4}")
    
    return {
        "CBC Plaintext 1": plaintext_1,
        "CBC Plaintext 2": plaintext_2,
        "CTR Plaintext 1": plaintext_3,
        "CTR Plaintext 2": plaintext_4
    }

# Run the solver
results = solve_all_problems()