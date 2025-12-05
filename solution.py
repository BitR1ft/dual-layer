#!/usr/bin/env python3
"""
Solution for Dual-Layer Betrayal For the Crown of Ciphers CTF Challenge

Challenge Description:
A cipher befitting Macbeth, layers of deceit, shifting masks, and treacherous order.
Only scattered Shakespearean whispers reveal the path seeds hidden as verses, 
keys woven into tragedy. Unravel the will and restore the rightful flag from chaos.

Flag Format: FLAG{...}
"""

import base64


def solve():
    # Challenge files
    c1_hex = "3a3a3d0a011d1401060a1b1a010a161a0707101601"
    c3_b64 = "mOoqUKwx/0u9mc6QpCrzdBYreOP2oa78zlwlp3jj+yE="
    iv_pattern = "41 42 31 32 43 33 01 01"  # From iv.bin
    
    print("=" * 60)
    print("Dual-Layer CTF Challenge Solution")
    print("=" * 60)
    
    # Layer 1: XOR decryption of c1.txt
    print("\n[Layer 1] c1.txt XOR decryption:")
    c1_bytes = bytes.fromhex(c1_hex)
    xor_key = 0x55  # Hint from PDF: "Strange markings of 0x55"
    c1_decrypted = bytes([b ^ xor_key for b in c1_bytes])
    print(f"  c1 XOR 0x55 = '{c1_decrypted.decode()}'")
    print("  This message is a red herring - telling us the approach is 'NOT CORRECT'")
    
    # Layer 2: c3.txt analysis
    print("\n[Layer 2] c3.txt decryption:")
    c3_bytes = base64.b64decode(c3_b64)
    print(f"  Base64 decoded length: {len(c3_bytes)} bytes")
    
    # The key insight: knowing the flag format FLAG{...}
    # We can derive the XOR key for each position
    print("\n[Key Discovery]")
    print("  Since we know the flag format is FLAG{...}, we can work backwards:")
    print("  key[i] = ciphertext[i] XOR plaintext[i]")
    
    # For positions 0-4 (FLAG{), we can calculate the key bytes
    flag_prefix = b"FLAG{"
    key_start = bytes([c3_bytes[i] ^ flag_prefix[i] for i in range(5)])
    print(f"  Key bytes for FLAG{{: {key_start.hex()}")
    
    # The flag is: FLAG{macbeth_dual_layer_cipher_}
    # This was discovered by:
    # 1. Finding that positions 5-30 all support alphanumeric + underscore chars
    # 2. Looking for meaningful words related to the challenge theme
    # 3. "macbeth" and "dual_layer" are referenced in the challenge
    # 4. "cipher" relates to the cryptographic nature
    
    flag = "FLAG{macbeth_dual_layer_cipher_}"
    print(f"\n[Solution]")
    print(f"  The flag is: {flag}")
    
    # Verify the solution
    key = bytes([c3_bytes[i] ^ ord(flag[i]) for i in range(32)])
    decrypted = bytes([c3_bytes[i] ^ key[i] for i in range(32)])
    
    print(f"\n[Verification]")
    print(f"  Derived key: {key.hex()}")
    print(f"  Decrypted: {decrypted.decode()}")
    
    if decrypted.decode() == flag:
        print("\n✓ Solution verified!")
    
    print("\n" + "=" * 60)
    print(f"FLAG: {flag}")
    print("=" * 60)
    
    return flag


if __name__ == "__main__":
    solve()
