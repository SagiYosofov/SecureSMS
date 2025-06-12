from typing import Union
from e_c_d_h.elliptic_curve import Point
from person import Person


class Receiver(Person):

    def __init__(self):
        super().__init__()

        self.sender_diffie_hellman_pk: Union[None, Point] = None
        self.decryption_key = None
        self.decrypted_ciphertext: Union[None, str] = None

    def extract_final_decryption_key(self):
        self.decryption_key = super().extract_final_key()
