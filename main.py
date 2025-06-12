from galois import GF

from e_c_d_h.diffie_hellman import EllipticCurveDiffieHellman
from e_c_d_h.elliptic_curve import EllipticCurve, Point
from ofb_mode import OFBMode
from rabin_signature import RabinDigitalSignature

BLOCK_SIZE = 16


def test_cryptographic_components():
    """Elliptic Curve Diffie-Hellman Exchange"""

    # public part
    p = 3851
    GFp = GF(p)

    # Totally insecure curve: y^2 = x^3 + 324x + 1287
    curve = EllipticCurve(a=GFp(324), b=GFp(1287))
    base_point = Point(curve, GFp(920), GFp(303))  # Known point of order 1964

    ecdh = EllipticCurveDiffieHellman(curve, base_point, p)

    # Generate secret keys
    alice_sk = ecdh.generate_secret_key()
    bob_sk = ecdh.generate_secret_key()
    print(f"Secret keys are {alice_sk}, {bob_sk}")

    # Generate public keys
    alice_pk = ecdh.compute_public_key(alice_sk)
    bob_pk = ecdh.compute_public_key(bob_sk)

    # Compute shared secrets
    shared_secret_alice = ecdh.compute_shared_secret(alice_sk, bob_pk)
    shared_secret_bob = ecdh.compute_shared_secret(bob_sk, alice_pk)

    print(f"Shared secret is {shared_secret_alice} == {shared_secret_bob}")
    print(shared_secret_alice == shared_secret_bob)

    # Extract usable integer from the x-coordinate
    print(f"x_coordinate: {shared_secret_alice.x}")

    # alice key for encrypting
    # Extract usable integer from the x-coordinate
    x_alice_int = int(shared_secret_alice.x)
    # Convert to bytes and then to list of integers
    x_alice_key_bytes = x_alice_int.to_bytes(BLOCK_SIZE, byteorder='big')
    alice_final_key = list(x_alice_key_bytes)

    # bob key for decrypting
    # Extract usable integer from the x-coordinate
    x_bob_int = int(shared_secret_bob.x)
    # Convert to bytes and then to list of integers
    x_bob_key_bytes = x_bob_int.to_bytes(BLOCK_SIZE, byteorder='big')
    bob_final_key = list(x_bob_key_bytes)


    # Test FROG Encryption and Decryption
    print("\n--- FROG Encryption and Decryption Test ---")

    # Alice decides on a message to send to Bob
    message = "Hi fella, how are you coping?"  # Original message
    print("Original Message:", message)

    # Alice encrypts the message and to sends to Bob
    ofb_mode_obj = OFBMode()
    cipher_text = ofb_mode_obj.ofb_encrypt(message, alice_final_key)
    print("Encrypted Message:", cipher_text)

    # Alice creates digital signature and sends to Bob
    rabin_signature = RabinDigitalSignature(512)
    digital_signature = rabin_signature.get_signature(cipher_text)

    # Bob gets the messages from Alice and decrypts it.
    # Decrypt the ciphertext
    decrypted_cipher_text = ofb_mode_obj.ofb_decrypt(cipher_text, bob_final_key)
    print("Decrypted Message:", decrypted_cipher_text)
    print(message == decrypted_cipher_text)

    # Bob gets from Alice the digital signature and verifies it.
    print(f"is digital signature valid? {rabin_signature.verify_signature(cipher_text,digital_signature)}")


if __name__ == "__main__":
    test_cryptographic_components()
