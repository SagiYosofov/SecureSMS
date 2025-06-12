import hashlib

from sympy import randprime
import random


class RabinDigitalSignature:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length
        # private key
        self.p, self.q = self.create_private_key()
        # public key
        self.n = self.p * self.q
        self.b = random.randint(0, self.n - 1)


    def generate_prime_mod_4_eq_3(self):
        """
        Generate a prime number of the given bit length that is congruent to 3 mod 4.

        Parameters:
            bit_length (int): Bit length of the prime number.

        Returns:
            int: A prime number p such that p ≡ 3 (mod 4).
        """
        lower_bound = 2 ** (self.bit_length - 1)
        upper_bound = 2 ** self.bit_length - 1

        while True:
            # Generate a random odd number in the range
            candidate = randprime(lower_bound, upper_bound)

            # Ensure it's ≡ 3 mod 4 and a prime
            if candidate % 4 == 3:
                return candidate

    def create_private_key(self):
        p = self.generate_prime_mod_4_eq_3()
        q = self.generate_prime_mod_4_eq_3()
        while q == p:
            q = self.generate_prime_mod_4_eq_3()

        return p, q

    def get_private_key(self):
        return self.p, self.q

    def get_public_key(self):
        return self.n, self.b

    def get_signature(self, msg: str):
        k_bits = 60
        u: str = RabinDigitalSignature.get_random_string(k_bits)
        c: int = RabinDigitalSignature.get_hash_value(msg + u)
        d = (self.b * RabinDigitalSignature.mod_inverse(2,self.n)) % self.n
        c_plus_d_square = c + d * d

        i=0
        while not (RabinDigitalSignature.is_quadratic_residue(c_plus_d_square, self.p)
                   and RabinDigitalSignature.is_quadratic_residue(c_plus_d_square, self.q)):
            u: str = RabinDigitalSignature.get_random_string(k_bits)
            c: int = RabinDigitalSignature.get_hash_value(msg + u)
            c_plus_d_square = c + d * d

            i+=1
            if i%100 == 0:
                print(i)

        sqrt_p = RabinDigitalSignature.square_root_mod_prime(c_plus_d_square, self.p)
        sqrt_q = RabinDigitalSignature.square_root_mod_prime(c_plus_d_square, self.q)

        x_p = (-d + sqrt_p) % self.p
        x_q = (-d + sqrt_q) % self.q

        # Use Chinese Remainder Theorem to find x such that:
        # x ≡ x_p (mod p)
        # x ≡ x_q (mod q)
        x = RabinDigitalSignature.chinese_remainder_theorem(x_p, self.p, x_q, self.q)

        # Return signature (u, x)
        return u, x

    @staticmethod
    def mod_inverse(a, n):
        """
        Compute the modular inverse of a modulo n, i.e., find x such that (a * x) % n == 1.
        Uses the Extended Euclidean Algorithm.
        Raises an exception if the inverse does not exist (i.e., a and n are not coprime).
        """
        t, new_t = 0, 1
        r, new_r = n, a

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError(f"{a} has no modular inverse modulo {n}")

        if t < 0:
            t = t + n

        return t

    def verify_signature(self, msg: str, signature):
        """
        Verify a Rabin signature
        """
        u, x = signature

        # Recompute hash
        c = RabinDigitalSignature.get_hash_value(msg + u)

        expected = c % self.n

        actual = x*(x + self.b) % self.n

        return actual == expected

    @staticmethod
    def is_quadratic_residue(a, p):
        """
        Returns True if 'a' is a quadratic residue modulo prime 'p', else False.
        According to Euler's Criterion.

        Parameters:
        - a (int): The integer to test
        - p (int): A prime modulus

        Returns:
        - bool: True if quadratic residue, False otherwise
        """
        if p <= 2:
            raise ValueError("p must be an odd prime greater than 2")
        a = a % p
        if a == 0:
            return True  # 0 is always a quadratic residue

        # Compute Euler's criterion
        legendre_symbol = pow(a, (p - 1) // 2, p)
        return legendre_symbol == 1

    @staticmethod
    def get_random_string(size) -> str:
        res = ""
        for i in range(size):
            res += str((random.randint(0, 1)))
        return res

    @staticmethod
    def get_hash_value(st: str) -> int:
        return int.from_bytes(hashlib.sha256(st.encode()).digest(), 'big')

    @staticmethod
    def square_root_mod_prime(a, p):
        """
        Compute square root of a modulo prime p
        Assumes p ≡ 3 (mod 4) for simplicity
        """
        return pow(a, (p + 1) // 4, p)

    @staticmethod
    def chinese_remainder_theorem(a1, m1, a2, m2):
        """
        Solve the system of two congruences:
            x ≡ a1 (mod m1)
            x ≡ a2 (mod m2)

        Assumes m1 and m2 are coprime.

        Returns:
            The smallest non-negative solution x modulo (m1 * m2)
        """

        def extended_gcd(a, b):
            """
            Extended Euclidean Algorithm.
            Returns (gcd, x, y) such that: a*x + b*y = gcd(a, b)
            """

            if a == 0:
                return b, 0, 1

            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, m1_inv, _ = extended_gcd(m1, m2)

        # Make sure m1_inv is positive
        m1_inv = m1_inv % m2

        # Combine the two congruences into a single result modulo (m1 * m2)
        diff = (a2 - a1) % m2
        correction = (diff * m1_inv) % m2
        x = (a1 + m1 * correction) % (m1 * m2)

        return x