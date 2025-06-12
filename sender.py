import random
from typing import Union
from person import Person
from e_c_d_h.elliptic_curve import Point


class Sender(Person):

    def __init__(self):
        super().__init__()

        self.receiver_diffie_hellman_pk: Union[None, Point] = None
        self.encryption_key = None

        self.plaintext: Union[None, str] = None

        self.digital_signature_sk_p: Union[None, int] = None
        self.digital_signature_sk_q: Union[None, int] = None

    def extract_final_encryption_key(self):
        """
        from the shared diffie hellman secret key we use just x coordinates (an integer)
        and convert it to list of bytes.
        """
        self.encryption_key = super().extract_final_key()

    def compute_digital_signature_public_key(self):
        """this function computes rabin digital signature public key based on
        the private keu"""
        if self.digital_signature_sk_p is None or self.digital_signature_sk_q is None:
            raise Exception("digital signature's private key doesn't exist !!")
        self.digital_signature_pk_n = self.digital_signature_sk_p * self.digital_signature_sk_q
        self.digital_signature_pk_b = random.randint(0, self.digital_signature_pk_n - 1)
