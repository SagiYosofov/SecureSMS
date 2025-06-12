import base64

from frog_encryption import make_key, frog_encrypt


class OFBMode:

    def __init__(self):
        self.iv: bytes = b'Q\x8d\xa4\x9e\xce\x10\xf9L\xe6\xa1H_\x94\x1diS'
        self.block_size = 16  # 128-bit block size for FROG
        self.n = 7  # bits to shift left.

    def shift_left_128bit(self, data_bytes: bytes) -> bytes:
        """Performs a circular left bit rotation on 128-bit data."""
        if len(data_bytes) != 16:
            raise ValueError("Input must be 16 bytes (128 bits).")

        # Convert bytes to integer
        data_int = int.from_bytes(data_bytes, byteorder='big')

        # Rotate left by n bits within 128-bit space
        rotated = ((data_int << self.n) | (data_int >> (128 - self.n))) & ((1 << 128) - 1)

        # Convert back to bytes
        return rotated.to_bytes(16, byteorder='big')

    def ofb_encrypt(self, plaintext: str, key: list[int]) -> str:
        """
        Implement OFB mode encryption
        :param plaintext: The text to encrypt
        :param key: The encryption key (list of integers from 0–255)
        :return: Ciphertext as a UTF-8 string (may not be safe if ciphertext contains non-text bytes)
        """

        # Convert plaintext to bytes
        plaintext = plaintext.encode('utf-8')

        # Pad plaintext using PKCS-style padding
        padding_length = self.block_size - (len(plaintext) % self.block_size)
        if padding_length == 0:
            padding_length = self.block_size
        plaintext += bytes([padding_length] * padding_length)

        cipher_bytes = bytearray()
        shift_register = list(self.iv)  # Convert IV to list[int]

        # Create FROG encryption key schedule
        frog_key = make_key(key)  # key should already be list[int] of length 16

        # Process plaintext in blocks
        for i in range(0, len(plaintext), self.block_size):
            plaintext_block = list(plaintext[i:i + self.block_size])  # list[int]

            # Encrypt shift register to generate keystream block
            key_stream_block = frog_encrypt(shift_register, frog_key.keyE)  # list[int]

            # XOR key stream with plaintext block
            ciphertext_block = [pt ^ ks for pt, ks in zip(plaintext_block, key_stream_block)]
            cipher_bytes.extend(ciphertext_block)

            # Update shift register: convert list[int] → bytes → shifted bytes → list[int]
            shift_register = list(self.shift_left_128bit(bytes(key_stream_block)))

        return base64.b64encode(cipher_bytes).decode('utf-8')  # return ciphertext as string

    def ofb_decrypt(self, ciphertext: str, key: list[int]) -> str:
        """
        Implement OFB mode decryption
        :param ciphertext: The encrypted text (encoded using 'latin1')
        :param key: The encryption key (list[int])
        :return: Decrypted plaintext as a string
        """

        # Decode ciphertext from 'latin1' to get the original bytes
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))  # reverses .decode('latin1') from encryption

        plaintext = bytearray()
        shift_register = list(self.iv)  # Convert IV to list[int]

        # Create FROG decryption key schedule
        frog_key = make_key(key)  # key should be list[int]

        # Process each block
        for i in range(0, len(ciphertext), self.block_size):
            ciphertext_block = list(ciphertext[i:i + self.block_size])  # list[int]

            # Generate key stream block by encrypting the shift register (OFB uses encryption only)
            key_stream_block = frog_encrypt(shift_register, frog_key.keyE)  # list[int]

            # XOR ciphertext block with key stream block to get plaintext block
            plaintext_block = [ct ^ ks for ct, ks in zip(ciphertext_block, key_stream_block)]
            plaintext.extend(plaintext_block)

            # Update shift register
            shift_register = list(self.shift_left_128bit(bytes(key_stream_block)))

        # Convert to bytes, then to string
        plaintext_bytes = bytes(plaintext)

        # Remove PKCS-style padding
        padding_length = plaintext_bytes[-1]
        if 0 < padding_length <= self.block_size:
            if all(p == padding_length for p in plaintext_bytes[-padding_length:]):
                plaintext_bytes = plaintext_bytes[:-padding_length]

        return plaintext_bytes.decode('utf-8')
