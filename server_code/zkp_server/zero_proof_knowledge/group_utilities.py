import secrets
import hashlib


class ZkpManager:
    """
    An object of this class acts as a manager that serves all the methods and information needed to execute a Zero Knowledge Proof to
    its inner classes: Prover and Verifier, which are built in order to provide facades to the protocol.
    """

    def __init__(self):
        """
        The values provided below as Zero Knowledge Proof parameters are the ones of "1024-bit MODP Group with 160-bit Prime Order Subgroup",
        as described in rfc5114 “Additional Diffie-Hellman Groups for Use with IETF Standards”
        link: https://www.ietf.org/rfc/rfc5114 by M.Lepinski S.Kent BBN Tecnologies”
        """
        self._x_test_hex = "B9A3B3AE 8FEFC1A2 93049650 7086F845 5D48943E"
        self._y_test_hex = "2A853B3D 92197501 B9015B2D EB3ED84F 5E021DCC 3E52F109 D3273D2B 7521281C BABE0E76 FF5727FA 8ACCE269 56BA9A1F CA26F202 28D8693F EB10841D 84A73600 54ECE5A7 F5B7A61A D3DFB3C6 0D2E4310 6D8727DA 37DF9CCE 95B47875 5D06BCEA 8F9D4596 5F75A5F3 D1DF3701 165FC9E5 0C4279CE B07F9895 40AE96D5 D88ED776"

        self._x_test = self.hex_to_int(self._x_test_hex)
        self._y_test = self.hex_to_int(self._y_test_hex)

        self._p_hex = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
        self._g_hex = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5"
        self._q_hex = "F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353"

        self._p = self.hex_to_int(self._p_hex)
        self._g = self.hex_to_int(self._g_hex)
        self._q = self.hex_to_int(self._q_hex)

    def get_p(self):
        return self._p

    def get_g(self):
        return self._g

    def get_q(self):
        return self._q

    def get_x_test(self):
        return self._x_test

    def get_y_test(self):
        return self._y_test

    def compute_c(self, string):
        """
        The method used to compute the challenge c is described here since Prover and Verifier have to share it.
        This implementation computes c as the sha256 hash of a given string.
        :param string: The string hashed in order to compute the challenge c.
        :return: The challenge c.
        """
        c = int(hashlib.sha256(string.encode("UTF-8")).hexdigest(), 16)
        return c

    @staticmethod
    def hex_to_int(hex_string):
        hex_no_space = hex_string.replace(' ', '')
        int_num = int(hex_no_space, 16)
        return int_num

    def get_random_element(self):
        """
        :return: A random element in a range [0, q-1].
        """
        element = secrets.randbelow(self.get_q())
        return element

    def pow(self, x):
        """
        Modular exponential as: y = g^x % p
        """
        g = self.get_g()
        p = self.get_p()
        y = pow(g, x, p)
        return y

    class _Prover:
        """
        An object of this class is used as facade to the methods useful in order to act as a prover in the Zero Knowledge Proof.
        """

        def __init__(self, zkp_manager, simulated=True, secret=None):
            """

            :param zkp_manager: The ZkpManager object used to provide to the Prover the groups parameters and methods.
            :param simulated: If True the secret used for the zkp is randomly generated, otherwise (if valid) the param "secret" is used.
            :param secret: The secret used in the zkp if the "simulated" parameter is set to False. Must be an integer.
            """
            self.zkp_manager = zkp_manager
            if not simulated and secret:
                self._x = secret
            else:
                self._x = self._compute_x()
            self._r = self._compute_r()
            self._a = self._compute_a()
            self._y = self._compute_y(self._x)
            self._c = None
            self._z = None

        def get_a(self):
            return self._a

        def get_z(self):
            return self._z

        def get_y(self):
            return self._y

        def _compute_y(self, x):
            return self.zkp_manager.pow(x)

        def _compute_x(self):
            x = self.zkp_manager.get_random_element()
            return x

        def _compute_r(self):
            r = self.zkp_manager.get_random_element()
            return r

        def _compute_a(self):
            a = self.zkp_manager.pow(self._r)
            return a

        def _compute_c(self, string):
            self._c = self.zkp_manager.compute_c(string)

        def _compute_z(self):
            self._z = (self._r - self._x * self._c) % self.zkp_manager.get_q()

        def compute_parameters(self, to_hash_string):
            """
            Computes the parameters (c, z) used by the prover in the zkp.
            :param to_hash_string: The string hashed in order to compute the challenge c.
            :return:
            """
            self._compute_c(to_hash_string)
            self._compute_z()

    class _Verifier:
        """
        An object of this class is used as facade to the methods useful in order to act as a verifier in the Zero Knowledge Proof.
        """

        def __init__(self, zkp_manager):
            self.zkp_manager = zkp_manager

        def _compute_c(self, string):
            self._c = self.zkp_manager.compute_c(string)

        def compute_challenge(self, string):
            """
            A must-call method used to compute the challenge (c) used by the prover in the zkp.
            :param string: The string hashed in order to compute the challenge c.
            :return:
            """
            self._compute_c(string)

        def verify(self, y, a, z):
            """
            Evaluates if the given parameters act as proof of the given public information y.
            :param y: The (public) information of interest.
            :param a: One of the parameter a Prover must provide in order to check if they know the secret that generated y.
            :param z: One of the parameter a Prover must provide in order to check if they know the secret that generated y.
            :return: True if the provided parameters shows the knowledge of the secret that generated y.
            """
            g = self.zkp_manager.get_g()
            p = self.zkp_manager.get_p()
            c = self._c
            """
            The computation this way is much faster as explained in page 290 example 8.5
            of Introduction to Modern Cryptography (2nd Edition) - Katz, Lindell
            """
            verified = a == (pow(g, z, p) * pow(y, c, p)) % p
            return verified

    def new_prover(self, simulated=True, secret=None):
        """
        Factory method used to provide an instance of the class Prover.
        :param simulated: If True the secret used for the zkp is randomly generated, otherwise (if valid) the param "secret" is used.
        :param secret: The secret used in the zkp if the "simulated" parameter is set to False. Must be an integer.
        :return: An instance of the class Prover.
        """
        return self._Prover(zkp_manager=self, simulated=simulated, secret=secret)

    def new_verifier(self):
        """
        Factory method used to provide an instance of the class Verifier.
        :return: An instance of the class Verifier.
        """
        return self._Verifier(zkp_manager=self)
