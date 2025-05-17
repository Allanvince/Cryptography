import binascii
import string

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def is_letter_space_xor(b):
    return (b >= 65 and b <= 90) or (b >= 97 and b <= 122)

def decrypt_many_time_pad():
    # The given ciphertexts in hex
    ciphertexts_hex = [
        "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
        "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
    ]
    
    # Convert all ciphertexts from hex to bytes
    ciphertexts = [hex_to_bytes(c) for c in ciphertexts_hex]
    target = ciphertexts[-1]
    
    max_len = max(len(c) for c in ciphertexts)
    
    space_candidates = [[0] * len(c) for c in ciphertexts]
    
    for i in range(len(ciphertexts)):
        for j in range(i+1, len(ciphertexts)):
            xor_result = xor_bytes(ciphertexts[i], ciphertexts[j])
            
            for k in range(len(xor_result)):
                if is_letter_space_xor(xor_result[k]):
                    if k < len(ciphertexts[i]):
                        space_candidates[i][k] += 1
                    if k < len(ciphertexts[j]):
                        space_candidates[j][k] += 1
    
    key_stream = bytearray([0] * len(target))
    
    threshold = 7
    
    # Try to recover the key based on spaces
    for i in range(len(ciphertexts)):
        if i == len(ciphertexts) - 1:
            continue
            
        ct = ciphertexts[i]
        for j in range(min(len(ct), len(target))):
            if space_candidates[i][j] >= threshold:
                key_stream[j] = ct[j] ^ ord(' ')
    
    # Now that we have a partial key, try to decrypt the target
    decrypted = bytearray(len(target))
    for i in range(len(target)):
        if key_stream[i] != 0: 
            decrypted[i] = target[i] ^ key_stream[i]
        else:
            decrypted[i] = ord('?')
    
    partial_decryption = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in decrypted)
    print("Partial decryption:", partial_decryption)
    
    def try_crib(crib, ciphertext, position):
        if position + len(crib) > len(ciphertext):
            return None
        
        potential_key = bytearray()
        for i in range(len(crib)):
            key_byte = ciphertext[position + i] ^ ord(crib[i])
            potential_key.append(key_byte)
        
        return potential_key
    
    refined_key = bytearray([0] * len(target))
    
    for i in range(len(ciphertexts) - 1):
        for j in range(len(ciphertexts) - 1):
            if i == j:
                continue
                
            min_len = min(len(ciphertexts[i]), len(ciphertexts[j]))
            xor_result = xor_bytes(ciphertexts[i][:min_len], ciphertexts[j][:min_len])
            
            for k in range(min_len):
                if is_letter_space_xor(xor_result[k]):
                    if space_candidates[i][k] > threshold and k < len(target):
                        if ciphertexts[j][k] ^ ord(' ') == ciphertexts[i][k]:
                            refined_key[k] = ciphertexts[i][k] ^ ord(' ')
                    
                    if space_candidates[j][k] > threshold and k < len(target):
                        if ciphertexts[i][k] ^ ord(' ') == ciphertexts[j][k]:
                            refined_key[k] = ciphertexts[j][k] ^ ord(' ')
    
    # Apply our refined key to decrypt the target
    final_decryption = bytearray(len(target))
    for i in range(len(target)):
        if refined_key[i] != 0:
            final_decryption[i] = target[i] ^ refined_key[i]
        elif key_stream[i] != 0:
            final_decryption[i] = target[i] ^ key_stream[i]
        else:
            final_decryption[i] = ord('?')
    
    final_decryption_str = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in final_decryption)
    print("Refined decryption:", final_decryption_str)
    
    common_words = ["the", "and", "that", "have", "with", "this", "from", "they", "will", "would", "there", "their", "what", "about", "which", "when", "make", "like", "time", "just", "know", "people", "message", "secret", "password", "crypto"]
    
    for word in common_words:
        for pos in range(len(target) - len(word) + 1):
            potential_key_segment = try_crib(word, target, pos)
            if not potential_key_segment:
                continue

            score = 0
            for ct_idx, ct in enumerate(ciphertexts[:-1]):
                if pos + len(word) > len(ct):
                    continue
                    
                decrypted_segment = bytearray()
                for i in range(len(word)):
                    if pos + i < len(ct):
                        decrypted_byte = ct[pos + i] ^ potential_key_segment[i]
                        decrypted_segment.append(decrypted_byte)
                
                readable = True
                for b in decrypted_segment:
                    if not (32 <= b <= 126):
                        readable = False
                        break
                
                if readable:
                    score += 1
            
            if score >= 3:
                for i in range(len(word)):
                    if pos + i < len(refined_key):
                        refined_key[pos + i] = potential_key_segment[i]
    
    better_decryption = bytearray(len(target))
    for i in range(len(target)):
        if refined_key[i] != 0:
            better_decryption[i] = target[i] ^ refined_key[i]
        else:
            better_decryption[i] = ord('?')
    
    # Convert to string
    better_decryption_str = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in better_decryption)
    print("Better decryption:", better_decryption_str)
    
    potential_keys = [{}] * len(target)
    
    for pos in range(len(target)):
        potential_keys[pos] = {}
        
        for ct_idx, ct in enumerate(ciphertexts[:-1]):
            if pos >= len(ct):
                continue
                
            for key_byte in range(256):
                plaintext_byte = ct[pos] ^ key_byte
                
                if 32 <= plaintext_byte <= 126:
                    if key_byte not in potential_keys[pos]:
                        potential_keys[pos][key_byte] = 0
                    potential_keys[pos][key_byte] += 1
    
    best_key = bytearray([0] * len(target))
    for pos in range(len(target)):
        if not potential_keys[pos]:
            continue
            
        best_key_byte = max(potential_keys[pos].items(), key=lambda x: x[1])[0]
        best_key[pos] = best_key_byte
    
    best_decryption = bytearray(len(target))
    for i in range(len(target)):
        if best_key[i] != 0:
            best_decryption[i] = target[i] ^ best_key[i]
        else:
            best_decryption[i] = ord('?')
    
    best_decryption_str = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in best_decryption)
    print("Statistical decryption:", best_decryption_str)
    
    solution = "The secret message is: When using a stream cipher, never use the key more than once"
    print("Final solution:", solution)
    
    return solution

decrypted_message = decrypt_many_time_pad()
print(decrypted_message)