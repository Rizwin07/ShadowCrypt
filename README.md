# ShadowCrypt

Encrypted image steganography CLI — hides an AES-256-GCM encrypted message inside a PNG image using password-scattered LSB matching.

```
==============================
       AES STEGO TOOL
==============================

1. Encrypt / Hide message
2. Decrypt / Extract message
3. Check image capacity
4. Exit
```

## What it does

ShadowCrypt encrypts a text message with **AES-256-GCM** (authenticated encryption — tamper-evident, not just confidential), then embeds the ciphertext into a carrier image's pixel data using a **password-derived, scattered LSB-matching** scheme.

It is not "hide text in an image" — it's "encrypt text properly, then hide the ciphertext." Even if the hidden data is found, it cannot be read without the password.

## Features

- **AES-256-GCM** encryption with **PBKDF2-HMAC-SHA256** (200,000 iterations) key derivation — no raw password-as-key shortcuts.
- **Randomized bit placement** — embedding order is shuffled using a password-derived seed, instead of writing sequentially from the first pixel. Defeats detection techniques that specifically target sequential embedding.
- **LSB matching, not LSB replacement** — pixel values are nudged ±1 rather than having their last bit forcibly overwritten, avoiding the classic statistical fingerprint of naive LSB tools.
- **Capacity check** — see the maximum message size a given image can hold before attempting to encrypt.
- **Password confirmation** on encrypt, to prevent silent lockouts from typos.
- **Rich terminal UI** with clear success/error states.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python stego.py
```

Follow the interactive menu. To hide a message you'll need:
- A carrier image (any format PIL can read as input — the *output* is always PNG)
- Your message text
- A password (any length — it's run through PBKDF2, not used directly as the key)

To extract a message, you need the exact stego PNG output and the exact password used to hide it.

## How it works (short version)

1. The message is encrypted with AES-256-GCM using a key derived from your password + a random per-file salt.
2. The encrypted payload (length header + salt + nonce + ciphertext) is converted to bits.
3. A password-derived pseudo-random order determines *which* pixel channel each bit goes into — not sequential.
4. Each targeted pixel channel's value is nudged by ±1 (only if needed) to make its least-significant bit match the payload bit.
5. The result is saved as a new PNG. The original image is never modified.

Decryption reverses this: derive the same bit order from the password, read the bits back out, reconstruct the payload, then decrypt.

## Known limitations — read this before relying on it for anything real

- **Not robust to image editing or recompression.** Any filter, resize, color adjustment, or lossy re-save (e.g. JPEG conversion) destroys the embedded data. This is inherent to LSB-based steganography, not a bug.
- **Messaging apps will break it.** Apps like Telegram/WhatsApp recompress images sent as "photos" by default. Send the output PNG as a **file/document**, not a photo, or the payload will not survive transit.
- **Detectable ≠ decryptable.** A sufficiently advanced statistical or ML-based stego detector may still flag that *something* is hidden in the image, even with scattered LSB matching. That does **not** expose the message content — AES-256-GCM protects that regardless. Password strength is the actual security boundary of this tool, not the steganographic layer.
- **PNG output only.** JPEG output would destroy the embedded bits on save due to lossy compression, so output is hardcoded to PNG.

## Project background

Built as an independent project extending cryptographic and steganographic coursework, iterating from a working AES+LSB proof of concept through password confirmation, error handling, randomized embedding, and LSB matching to reduce detectability against common statistical stego-analysis tools.

## License

MIT
