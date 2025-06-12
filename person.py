from typing import Union

from e_c_d_h.elliptic_curve import Point

BLOCK_SIZE = 16


class Person:
    def __init__(self):
        self.diffie_hellman_sk: Union[None, int] = None
        self.diffie_hellman_pk: Union[None, Point] = None
        self.shared_diffie_hellman_sk: Union[None, Point] = None

        self.ciphertext: Union[None, str] = None

        self.digital_signature_pk_n: Union[None, int] = None
        self.digital_signature_pk_b: Union[None, int] = None

        self.digital_signature_u: Union[None, str] = None
        self.digital_signature_x: Union[None, str] = None

    def extract_final_key(self):
        if self.shared_diffie_hellman_sk is None:
            raise Exception("there isn't a shared secret key to extract from")

        # Extract usable integer from the x-coordinate
        x_coordinate = int(self.shared_diffie_hellman_sk.x)
        # Convert x coordinate to bytes
        x_coordinate_bytes = x_coordinate.to_bytes(BLOCK_SIZE, byteorder='big')
        # convert bytes to list of integers
        return list(x_coordinate_bytes)
