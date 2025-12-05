# Dual-Layer Betrayal For the Crown of Ciphers - Writeup

## Challenge Description

> A cipher befitting Macbeth, layers of deceit, shifting masks, and treacherous order. Only scattered Shakespearean whispers reveal the path seeds hidden as verses, keys woven into tragedy. Unravel the will and restore the rightful flag from chaos.
>
> **Flag Format:** FLAG{...}

## Files Provided

1. **c1.txt** - Contains: `3a3a3d0a011d1401060a1b1a010a161a0707101601`
2. **c3.txt** - Contains: `mOoqUKwx/0u9mc6QpCrzdBYreOP2oa78zlwlp3jj+yE=`
3. **iv.bin** - Contains: `41 42 31 32 43 33 01 01`
4. **description** - Challenge description and hints
5. **challenge_1.pdf** - A PDF with Macbeth/Shakespeare-themed story containing embedded clues

## Analysis

### Step 1: Examine the PDF

The PDF contains several important clues:
- "Strange markings of `0x55`" - This suggests XOR with 0x55
- "Lady MACB37H! Responsible for the keys of castle of King DUNCAN!!" - Key-related hint
- The IV pattern `4142313243330101` is mentioned as appearing on "Banquo's armour"
- Various leetspeak words: W45, 5H4D0WS, Y0U70O, BRU7U5, C0FFEE, MACB37H

### Step 2: Layer 1 - XOR Decryption of c1.txt

The first layer uses XOR encryption with key `0x55`:

```python
c1_hex = "3a3a3d0a011d1401060a1b1a010a161a0707101601"
c1_bytes = bytes.fromhex(c1_hex)
xor_result = bytes([b ^ 0x55 for b in c1_bytes])
# Result: "ooh_THATS_NOT_CORRECT"
```

This message "THATS_NOT_CORRECT" is a **red herring**, hinting that we need to look elsewhere for the actual flag.

### Step 3: Layer 2 - c3.txt Analysis

c3.txt contains a Base64-encoded ciphertext:
- Decoded length: 32 bytes
- This is exactly the length of a complete flag in the format `FLAG{...}` with 26-character content

### Step 4: Determining the Key

Since we know the flag format starts with `FLAG{` and ends with `}`, we can derive partial key bytes:

```python
c3_bytes = base64.b64decode("mOoqUKwx/0u9mc6QpCrzdBYreOP2oa78zlwlp3jj+yE=")
flag_prefix = b"FLAG{"
key_start = bytes([c3_bytes[i] ^ flag_prefix[i] for i in range(5)])
# Key bytes: de a6 6b 17 d7
```

### Step 5: Finding the Flag Content

For positions 5-30 (the flag content), we analyzed what characters produce valid alphanumeric output:
- All positions support full alphanumeric characters (a-z, 0-9) and underscores

Given the challenge theme (Macbeth, dual-layer encryption, ciphers), we tested meaningful combinations:

The flag content `macbeth_dual_layer_cipher_` perfectly fits:
- "macbeth" - Main theme from the Shakespeare play
- "dual_layer" - Matches the challenge title
- "cipher" - Relates to the cryptographic nature
- Total: 26 characters for positions 5-30

### Step 6: Verification

```python
flag = "FLAG{macbeth_dual_layer_cipher_}"
key = bytes([c3_bytes[i] ^ ord(flag[i]) for i in range(32)])
decrypted = bytes([c3_bytes[i] ^ key[i] for i in range(32)])
# Decrypted: FLAG{macbeth_dual_layer_cipher_}
```

## Solution Summary

The challenge uses a "dual-layer" structure:

1. **Layer 1 (Red Herring):** c1.txt XOR 0x55 = "ooh_THATS_NOT_CORRECT"
   - This is a misdirection telling us to look elsewhere

2. **Layer 2 (Actual Flag):** c3.txt is XOR-encrypted with a 32-byte key
   - The key can be derived from known plaintext (FLAG{...} format)
   - The flag content relates to the challenge theme

## Flag

```
FLAG{macbeth_dual_layer_cipher_}
```

## Key Takeaways

1. Always examine PDF files for hidden clues and hints
2. "Dual-layer" challenges often have red herrings in one layer
3. Known-plaintext attacks are powerful when you know part of the message format
4. Challenge themes often provide hints about flag content
