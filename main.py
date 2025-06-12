from galois import GF

from e_c_d_h.diffie_hellman import EllipticCurveDiffieHellman
from e_c_d_h.elliptic_curve import EllipticCurve, Point
from ofb_mode import OFBMode
from rabin_signature import RabinDigitalSignature
from receiver import Receiver
from sender import Sender

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

    alice = Sender()
    bob = Receiver()

    # Generate secret keys
    alice.diffie_hellman_sk = ecdh.generate_secret_key()
    bob.diffie_hellman_sk = ecdh.generate_secret_key()
    print(f"Secret keys are {alice.diffie_hellman_sk}, {bob.diffie_hellman_sk}")

    # Generate public keys
    alice.diffie_hellman_pk = ecdh.compute_public_key(alice.diffie_hellman_sk)
    bob.diffie_hellman_pk = ecdh.compute_public_key(bob.diffie_hellman_sk)

    # Alice sends her public key to Bob
    bob.sender_diffie_hellman_pk = alice.diffie_hellman_pk
    # Bob sends her public key to Alice
    alice.receiver_diffie_hellman_pk = bob.diffie_hellman_pk

    # Compute shared secret keys
    alice.shared_diffie_hellman_sk = ecdh.compute_shared_secret(alice.diffie_hellman_sk,
                                                                alice.receiver_diffie_hellman_pk)
    bob.shared_diffie_hellman_sk = ecdh.compute_shared_secret(bob.diffie_hellman_sk,
                                                              bob.sender_diffie_hellman_pk)

    # compute keys for encryption and decryption
    alice.extract_final_encryption_key()
    bob.extract_final_decryption_key()

    # Test FROG Encryption and Decryption
    print("\n--- FROG Encryption and Decryption Test ---")

    # Alice decides on a message to send to Bob
    alice.plaintext = input("Enter a message to send: ")

    # Alice encrypts the message and to sends to Bob
    ofb_mode_obj = OFBMode()
    alice.ciphertext = ofb_mode_obj.ofb_encrypt(alice.plaintext, alice.encryption_key)
    print("Encrypted Message:", alice.ciphertext)

    # Alice creates digital signature and sends to Bob
    rabin_signature = RabinDigitalSignature()
    # Alice creates public key for digital signature
    alice.digital_signature_sk_p, alice.digital_signature_sk_q = rabin_signature.generate_private_key()

    # Alice create public key for digital signature
    alice.compute_digital_signature_public_key()

    # Alice send to Bob the public key for digital signature
    bob.digital_signature_pk_n = alice.digital_signature_pk_n
    bob.digital_signature_pk_b = alice.digital_signature_pk_b

    digital_signature = rabin_signature.get_signature(msg=alice.ciphertext,
                                                      n=alice.digital_signature_pk_n,
                                                      b=alice.digital_signature_pk_b,
                                                      p=alice.digital_signature_sk_p,
                                                      q=alice.digital_signature_sk_q)
    alice.digital_signature_u, alice.digital_signature_x = digital_signature

    # Alice sends to Bob the cipher_text
    bob.ciphertext = alice.ciphertext

    # Alice sends to Bob the digital signature
    bob.digital_signature_u = alice.digital_signature_u
    bob.digital_signature_x = alice.digital_signature_x

    # Bob gets the messages from Alice and decrypts it.
    bob.decrypted_ciphertext = ofb_mode_obj.ofb_decrypt(bob.ciphertext, bob.decryption_key)
    print("Decrypted Message:", bob.decrypted_ciphertext)

    if alice.plaintext == bob.decrypted_ciphertext:
        print("Good decryption, the decrypted text is identical to the plaintext")
    else:
        print("Bad decryption, the decrypted text is NOT identical to the plaintext")

    # Bob gets from Alice the digital signature and verifies it.
    flag = rabin_signature.verify_signature(
        msg=bob.ciphertext,
        signature=(bob.digital_signature_u, bob.digital_signature_x),
        n=bob.digital_signature_pk_n,
        b=bob.digital_signature_pk_b
    )
    if not flag:
        raise Exception("Invalid digital signature !!\nWe can't trust on this message.")
    else:
        print("This is a valid digital signature !!\nWe can trust on this message.")

if __name__ == "__main__":
    test_cryptographic_components()
