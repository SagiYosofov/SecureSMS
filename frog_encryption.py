import numpy as np
from enum import Enum

# The size of a block in the cipher (FROG works on 16-byte blocks).
BLOCK_SIZE = 16

# Number of rounds in the FROG cipher's internal structure.
NUM_ITERATIONS = 8

# A predefined list of 251 bytes used as a source of randomness in key expansion.
randomSeed = [
    113, 21, 232, 18, 113, 92, 63, 157, 124, 193, 166, 197, 126, 56, 229, 229,
    156, 162, 54, 17, 230, 89, 189, 87, 169, 0, 81, 204, 8, 70, 203, 225,
    160, 59, 167, 189, 100, 157, 84, 11, 7, 130, 29, 51, 32, 45, 135, 237,
    139, 33, 17, 221, 24, 50, 89, 74, 21, 205, 191, 242, 84, 53, 3, 230,
    231, 118, 15, 15, 107, 4, 21, 34, 3, 156, 57, 66, 93, 255, 191, 3,
    85, 135, 205, 200, 185, 204, 52, 37, 35, 24, 68, 185, 201, 10, 224, 234,
    7, 120, 201, 115, 216, 103, 57, 255, 93, 110, 42, 249, 68, 14, 29, 55,
    128, 84, 37, 152, 221, 137, 39, 11, 252, 50, 144, 35, 178, 190, 43, 162,
    103, 249, 109, 8, 235, 33, 158, 111, 252, 205, 169, 54, 10, 20, 221, 201,
    178, 224, 89, 184, 182, 65, 201, 10, 60, 6, 191, 174, 79, 98, 26, 160,
    252, 51, 63, 79, 6, 102, 123, 173, 49, 3, 110, 233, 90, 158, 228, 210,
    209, 237, 30, 95, 28, 179, 204, 220, 72, 163, 77, 166, 192, 98, 165, 25,
    145, 162, 91, 212, 41, 230, 110, 6, 107, 187, 127, 38, 82, 98, 30, 67,
    225, 80, 208, 134, 60, 250, 153, 87, 148, 60, 66, 165, 72, 29, 165, 82,
    211, 207, 0, 177, 206, 13, 6, 14, 92, 248, 60, 201, 132, 95, 35, 215,
    118, 177, 121, 180, 27, 83, 131, 26, 39, 46, 12]


class ENCRYPTION(Enum):
    """Enum to distinguish between encryption and decryption modes."""
    ENCRYPT = False
    DECRYPT = True


class FrogIterKey:
    """Represents a single round key (subkey) in FROG cipher,
      holding three components: XOR mask, substitution permutation (S-box), and block permutation."""
    def __init__(self):
        """Initializes xorBu, SubstPermu, and BombPermu arrays with default values (zeroed out)."""

        self.xorBu: list[int] = [0] * BLOCK_SIZE
        '''
        Meaning: This is a block of bytes that will be XORed with the input (plaintext or intermediate ciphertext) during encryption/decryption.
        Role: It adds non-linearity and confusion. XORing is a common operation in block ciphers because it’s fast and reversible.
        '''

        self.SubstPermu: list[int] = [0] * 256
        '''
        Meaning: This is a substitution permutation array, essentially a substitution box (S-box) or mapping from byte values 0-255 to a rearranged version of those 256 values.
        Role: It provides non-linearity and helps resist differential and linear cryptanalysis.
        '''
        self.BombPermu: list[int] = [0] * BLOCK_SIZE
        '''
        Meaning: This is a block permutation. It maps each byte position in the block to another position.
        Role: It rearranges bytes in the block – essentially a byte-level permutation that enhances diffusion.
        '''

    @staticmethod
    def size() -> int:
        """
        :return: how many values make up one complete iteration key
        """
        return BLOCK_SIZE * 2 + 256

    def set_value(self, i, value) -> None:
        """
        Sets a value into the key components at index i.
        Behavior: Distributes value into xorBu, SubstPermu, or BombPermu based on the index.
        :param i: Index within the 288-length composite structure.
        :param value: Byte value to be stored.
        :return: None
        """
        if value < 0:
            value = 256 + value
        if i < BLOCK_SIZE:
            self.xorBu[i] = value
        elif i < BLOCK_SIZE + 256:
            self.SubstPermu[i - BLOCK_SIZE] = value
        else:
            self.BombPermu[i - BLOCK_SIZE - 256] = value

    def get_value(self, i) -> int:
        """Retrieves the value at index i from the corresponding key component."""
        if i < BLOCK_SIZE:
            return self.xorBu[i]
        elif i < BLOCK_SIZE + 256:
            return self.SubstPermu[i - BLOCK_SIZE]
        else:
            return self.BombPermu[i - BLOCK_SIZE - 256]

    def copy_from(self, origin) -> None:
        """Copies all key components from another FrogIterKey instance"""
        for i in range(len(origin.xorBu)):
            self.xorBu[i] = origin.xorBu[i]
        for i in range(len(origin.SubstPermu)):
            self.SubstPermu[i] = origin.SubstPermu[i]
        for i in range(len(origin.BombPermu)):
            self.BombPermu[i] = origin.BombPermu[i]


class FrogInternalKey:
    def __init__(self):
        self.internalKey = [FrogIterKey() for i in range(NUM_ITERATIONS)]
        self.keyE = [FrogIterKey() for i in range(NUM_ITERATIONS)]
        self.keyD = [FrogIterKey() for i in range(NUM_ITERATIONS)]

    def set_value(self, index, value) -> None:
        self.internalKey[index / FrogIterKey.size()].set_value(index % FrogIterKey.size(), value)

    def get_value(self, index) -> int:
        return self.internalKey[index / FrogIterKey.size()].get_value(index % FrogIterKey.size())


def frog_encrypt(plain_text: list[int], key: list[FrogIterKey]) -> list[int]:
    """
    Encrypt plainText using internalKey
    :param plain_text:  A list of 16 integers (0–255), representing the plaintext block or part of it.
    :param key: A list of FrogIterKey objects (length = NUM_ITERATIONS), each containing subkeys.
    :return: The encrypted plainText
    """
    for i in range(0, NUM_ITERATIONS):
        for j in range(0, BLOCK_SIZE):
            plain_text[j] = plain_text[j] ^ key[i].xorBu[j]
            if plain_text[j] < 0:
                plain_text[j] = key[i].SubstPermu[plain_text[j] + 256]
            else:
                plain_text[j] = key[i].SubstPermu[plain_text[j]]
            if j < BLOCK_SIZE - 1:
                plain_text[j + 1] = plain_text[j + 1] ^ plain_text[j]
            else:
                plain_text[0] = plain_text[0] ^ plain_text[BLOCK_SIZE - 1]
            plain_text[key[i].BombPermu[j]] ^= plain_text[j]
    return plain_text


def frog_decrypt(cipher_text: list[int], key: list[FrogIterKey]) -> list[int]:
    """
     Decrypts a 16-byte block using the FROG algorithm and a processed decryption key.
    :param cipher_text: list of integers (bytes) to decrypt
    :param key: A list of FrogIterKey objects (length = NUM_ITERATIONS), each containing subkeys.
    :return: The encrypted plainText block (in-place modified list of 16 bytes).
    """
    for i in reversed(range(0, NUM_ITERATIONS)):
        for j in reversed(range(0, BLOCK_SIZE)):
            cipher_text[key[i].BombPermu[j]] ^= cipher_text[j]
            if (j < BLOCK_SIZE - 1):
                cipher_text[j + 1] = cipher_text[j + 1] ^ cipher_text[j]
            else:
                cipher_text[0] = cipher_text[0] ^ cipher_text[BLOCK_SIZE - 1]
            if cipher_text[j] < 0:
                cipher_text[j] = key[i].SubstPermu[cipher_text[j] + 256]
            else:
                cipher_text[j] = key[i].SubstPermu[cipher_text[j]]
            cipher_text[j] = cipher_text[j] ^ key[i].xorBu[j]
    return cipher_text


def make_internal_key(decrypting: ENCRYPTION, key_origin: list[FrogIterKey]) -> list[FrogIterKey]:
    '''
    Processes a raw key into a usable encryption/decryption key schedule, by creating valid permutations and transformations.
    :param decrypting: An ENCRYPTION enum (ENCRYPT or DECRYPT) that specifies the key direction.
    :param key_origin: A list of FrogIterKey objects initialized from the raw key.
    :return: A list of processed FrogIterKey objects (length = NUM_ITERATIONS)
    '''

    used = [0] * BLOCK_SIZE  # A list used to track which positions are already used in a permutation cycle (size = block size).
    key = [FrogIterKey() for i in
           range(NUM_ITERATIONS)]  # New list of FrogIterKey objects that will hold the internal, processed key.
    k = 0
    l = 0
    h = 0

    # Copy the Original Key into the Internal Structure
    for i in range(0, NUM_ITERATIONS):
        key[i] = FrogIterKey()
        key[i].copy_from(key_origin[i])

    for i in range(0, NUM_ITERATIONS):
        # Turns the substitution array into a valid permutation
        key[i].SubstPermu = make_permutation(key[i].SubstPermu)

        if (decrypting.value):
            key[i].SubstPermu = invert_permutation(key[i].SubstPermu)

        # Build & Fix the Bomb Permutation (Diffusion)
        key[i].BombPermu = make_permutation(key[i].BombPermu)

        # Cycle Fixing — Eliminate Zero Loops
        for j in range(0, BLOCK_SIZE):
            used[j] = 0

        for j in range(0, BLOCK_SIZE - 1):
            if (key[i].BombPermu[h] == 0):
                k = h
                while True:
                    k = (k + 1) % BLOCK_SIZE
                    # If the current value maps to 0 — this could create a loop too early in the permutation cycle
                    if used[k] == 0:
                        break
                key[i].BombPermu[h] = k
                l = k
                while key[i].BombPermu[l] != k:
                    l = key[i].BombPermu[l]
                key[i].BombPermu[l] = 0
            used[h] = 1
            h = key[i].BombPermu[h]
        for ind in range(0, BLOCK_SIZE):
            if ind == BLOCK_SIZE - 1:
                h = 0
            else:
                h = ind + 1
            if key[i].BombPermu[ind] == h:
                if (h == BLOCK_SIZE - 1):
                    k = 0
                else:
                    k = h + 1
                key[i].BombPermu[ind] = k

    return key


def hash_key(raw_key: list[int]) -> list[FrogIterKey]:
    """
    The hashKey() function is a key expansion routine for the FROG cipher.
    It transforms a raw user-provided key (binaryKey) into an internal key schedule that the FROG algorithm uses for encryption and decryption.
    :param binaryKey: A list of integers (raw key bytes) of arbitrary length.
    :return: A list of FrogIterKey objects (internalKey) used to derive encryption and decryption subkeys.
    """
    buffer = [0] * BLOCK_SIZE
    simpleKey = [FrogIterKey() for i in range(NUM_ITERATIONS)]
    internalKey = [FrogIterKey() for i in range(NUM_ITERATIONS)]

    keyLen = len(raw_key)
    sizeKey = FrogIterKey.size() * NUM_ITERATIONS  # 2304
    iSeed = 0
    iFrase = 0
    for i in range(0, sizeKey):
        simpleKey[i // FrogIterKey.size()].set_value(i % FrogIterKey.size(), randomSeed[iSeed] ^ raw_key[iFrase])
        if iSeed < 250:
            iSeed = iSeed + 1
        else:
            iSeed = 0
        if iFrase < keyLen - 1:
            iFrase = iFrase + 1
        else:
            iFrase = 0
    simpleKey = make_internal_key(ENCRYPTION.ENCRYPT, simpleKey)
    for i in range(0, BLOCK_SIZE):
        buffer[i] = 0
    last = keyLen - 1
    if (last > BLOCK_SIZE):
        last = BLOCK_SIZE - 1
    for i in range(0, last + 1):
        buffer[i] ^= raw_key[i]
    buffer[0] ^= keyLen

    position = 0

    while True:
        buffer = frog_encrypt(buffer,
                              simpleKey)  # This step adds nonlinearity and diffusion, making the key expansion secure.
        size = sizeKey - position
        if (size > BLOCK_SIZE):
            size = BLOCK_SIZE
        for i in range(0, BLOCK_SIZE):
            if (buffer[i] < 0):
                internalKey[(position + i) // FrogIterKey.size()].set_value((position + i) % FrogIterKey.size(),
                                                                            buffer[i] + 256)
            else:
                internalKey[(position + i) // FrogIterKey.size()].set_value((position + i) % FrogIterKey.size(),
                                                                            buffer[i])
        position = position + size
        if position == sizeKey:
            break
    return internalKey


def make_permutation(permu: list[int]) -> list[int]:
    """
    Converts a list of integers into a valid permutation (each number 0–n appears once, no repeats).
    :param permu: A list of integers (pseudo-random input values).
    :return: A modified list (permu) that is a valid permutation of numbers [0, len(permu)-1].
    """
    use = [0] * 256  # these are the candidate values for the permutation.
    lastElem = len(permu) - 1  # The last valid index in the permutation.
    last = lastElem  # Tracks the end of the use list as elements are removed.
    j = 0
    # initialize use array
    for i in range(0, lastElem + 1):
        use[i] = i

    for i in range(0, lastElem):
        j = (j + permu[i]) % (last + 1)  # j is updated using permu[i] to get a new position (introducing randomness).
        permu[i] = use[j]
        # Remove use[index] value from use array
        if j < last:
            for k in range(j, last):
                use[k] = use[k + 1]
        last = last - 1
        if j > last:
            j = last
    permu[lastElem] = use[0]
    return permu


def invert_permutation(orig_permu: list[int]) -> list[int]:
    """
    Computes the inverse of a given permutation.
    :param orig_permu: A permutation list (e.g., from makePermutation).
    :return: invPermu: The inverse permutation, such that invPermu[origPermu[i]] == i.
    """
    # Receives a permutation and returns its inverse
    invPermu = [0] * 256
    for i in range(0, len(orig_permu)):
        invPermu[orig_permu[i]] = i
    return invPermu


def make_key(k: list[int]) -> FrogInternalKey:
    """
    Generates a complete encryption/decryption key schedule from a user-provided key.
    :param k: A list of integers (raw key bytes).
    :return: FrogInternalKey object containing:
                                internalKey: Expanded key
                                keyE: Encryption subkeys
                                keyD: Decryption subkeys
    """
    intKey = FrogInternalKey()
    intKey.internalKey = hash_key(k)
    intKey.keyE = make_internal_key(ENCRYPTION.ENCRYPT, intKey.internalKey)
    intKey.keyD = make_internal_key(ENCRYPTION.DECRYPT, intKey.internalKey)
    return intKey
