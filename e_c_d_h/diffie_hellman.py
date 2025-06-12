from galois import GF

from e_c_d_h.elliptic_curve import EllipticCurve, Point  # Relative import
import random


class EllipticCurveDiffieHellman:
    def __init__(self, curve: EllipticCurve, base_point: Point, field_order: int):
        self.curve = curve
        self.base_point = base_point
        self.p = field_order

    def generate_secret_key(self):
        return random.randint(1, self.p - 1)

    def compute_public_key(self, private_key):
        return private_key * self.base_point

    def compute_shared_secret(self, private_key, other_public_key):
        return private_key * other_public_key


if __name__ == "__main__":
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





    # p = 3851
    # GFp = GF(p)
    #
    # # Totally insecure curve: y^2 = x^3 + 324x + 1287
    # curve = EllipticCurve(a=GFp(324), b=GFp(1287))
    #
    # basePoint = Point(curve, GFp(920), GFp(303))  # Known point of order 1964
    #
    # aliceSecretKey = generateSecretKey(p)
    # bobSecretKey = generateSecretKey(p)
    #
    # print('Secret keys are %d, %d' % (aliceSecretKey, bobSecretKey))
    #
    # alicePublicKey = sendDH(aliceSecretKey, basePoint, lambda x: x)
    # bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x: x)
    #
    # sharedSecret1 = receiveDH(bobSecretKey, lambda: alicePublicKey)
    # sharedSecret2 = receiveDH(aliceSecretKey, lambda: bobPublicKey)
    #
    # print('Shared secret is %s == %s' % (sharedSecret1, sharedSecret2))
    # print(sharedSecret1 == sharedSecret2)
    # print(f"Extracting x-coordinate to get an integer shared secret: {int(sharedSecret1.x)}")
