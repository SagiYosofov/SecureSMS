from galois import GF

from e_c_d_h.diffie_hellman import EllipticCurveDiffieHellman
from e_c_d_h.elliptic_curve import EllipticCurve, Point
from ofb_mode import OFBMode
from rabin_signature import RabinDigitalSignature
from receiver import Receiver
from sender import Sender

BLOCK_SIZE = 16


def test_cryptographic_components():
    """Elliptic Curve Diffie-Hellman Key Exchange"""
    # public part
    p = 3851
    GFp = GF(p)

    # Totally insecure curve: y^2 = x^3 + 324x + 1287
    curve = EllipticCurve(a=GFp(324), b=GFp(1287))
    base_point = Point(curve, GFp(920), GFp(303))  # Known point of order 1964

    ecdh = EllipticCurveDiffieHellman(curve, base_point, p)

    alice = Sender()
    bob = Receiver()
    print("Alice wakes up and the morning and sends to Bob a message\n")

    print("Alice and Bob generate secret keys for key exchange")
    alice.diffie_hellman_sk = ecdh.generate_secret_key()
    bob.diffie_hellman_sk = ecdh.generate_secret_key()
    print(f"Alice's secret key: {alice.diffie_hellman_sk}")
    print(f"Bob's secret key: {bob.diffie_hellman_sk}\n")

    print("Alice and Bob generate public keys for key exchange")
    alice.diffie_hellman_pk = ecdh.compute_public_key(alice.diffie_hellman_sk)
    bob.diffie_hellman_pk = ecdh.compute_public_key(bob.diffie_hellman_sk)
    print(f"Alice's public key: {alice.diffie_hellman_pk}")
    print(f"Bob's public key: {bob.diffie_hellman_pk}\n")

    print("Alice sends her public key to Bob")
    bob.sender_diffie_hellman_pk = alice.diffie_hellman_pk
    print("Bob sends his public key to Alice\n")
    alice.receiver_diffie_hellman_pk = bob.diffie_hellman_pk

    print("Alice and Bob compute their shared secret key")
    alice.shared_diffie_hellman_sk = ecdh.compute_shared_secret(alice.diffie_hellman_sk,
                                                                alice.receiver_diffie_hellman_pk)
    bob.shared_diffie_hellman_sk = ecdh.compute_shared_secret(bob.diffie_hellman_sk,
                                                              bob.sender_diffie_hellman_pk)
    print(f"Alice's shared secret key: {alice.shared_diffie_hellman_sk}")
    print(f"Bob's shared secret key: {bob.shared_diffie_hellman_sk}\n")

    # compute keys for encryption and decryption
    alice.extract_final_encryption_key()
    bob.extract_final_decryption_key()

    """FROG Encryption"""
    alice.plaintext = input("Enter a message for Alice to send: ")

    print("\nAlice encrypts the message using Frog cipher")
    ofb_mode_obj = OFBMode()
    alice.ciphertext = ofb_mode_obj.ofb_encrypt(alice.plaintext, alice.encryption_key)
    print(f"Encrypted Message: {alice.ciphertext}\n")

    """Rabin Digital Signature"""
    print("Alice creates digital signature using Rabin Digital Signature")
    rabin_signature = RabinDigitalSignature()

    print("Alice creates private key for digital signature")
    alice.digital_signature_sk_p, alice.digital_signature_sk_q = rabin_signature.generate_private_key()
    print(
        f"Alice's digital signature private key:\np={alice.digital_signature_sk_p}\nq={alice.digital_signature_sk_q}\n")

    print("Alice creates public key for digital signature")
    alice.compute_digital_signature_public_key()
    print(
        f"Alice's digital signature public key:\nn={alice.digital_signature_pk_n}\nb={alice.digital_signature_pk_b}\n")

    print("Alice sends to Bob the public key for digital signature\n")
    bob.digital_signature_pk_n = alice.digital_signature_pk_n
    bob.digital_signature_pk_b = alice.digital_signature_pk_b

    print("Alice computes the digital signature for her message")
    digital_signature = rabin_signature.get_signature(msg=alice.ciphertext,
                                                      n=alice.digital_signature_pk_n,
                                                      b=alice.digital_signature_pk_b,
                                                      p=alice.digital_signature_sk_p,
                                                      q=alice.digital_signature_sk_q)
    alice.digital_signature_u, alice.digital_signature_x = digital_signature
    print(f"digital signature:\nu={alice.digital_signature_u}\nx={alice.digital_signature_x}\n")

    print("Alice sends to Bob the cipher_text")
    bob.ciphertext = alice.ciphertext

    print("Alice sends to Bob the digital signature\n")
    bob.digital_signature_u = alice.digital_signature_u
    bob.digital_signature_x = alice.digital_signature_x

    print("Bob gets the message from Alice and decrypts it.")
    bob.decrypted_ciphertext = ofb_mode_obj.ofb_decrypt(bob.ciphertext, bob.decryption_key)
    print("Decrypted Message:", bob.decrypted_ciphertext)

    if alice.plaintext == bob.decrypted_ciphertext:
        print("Good decryption, the decrypted text is identical to the plaintext")
    else:
        print("Bad decryption, the decrypted text is NOT identical to the plaintext")

    print("\nBob gets from Alice the digital signature and verifies it")
    is_good_signature = rabin_signature.verify_signature(
        msg=bob.ciphertext,
        signature=(bob.digital_signature_u, bob.digital_signature_x),
        n=bob.digital_signature_pk_n,
        b=bob.digital_signature_pk_b
    )
    if is_good_signature:
        print("Valid digital signature\nThis message can be trusted")
    else:
        print("Invalid digital signature\nThis message cannot be trusted")


if __name__ == "__main__":
    test_cryptographic_components()
