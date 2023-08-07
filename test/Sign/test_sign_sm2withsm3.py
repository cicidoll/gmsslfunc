import unittest, sys
sys.path.append('.')

from Sign.SM2withSM3Der import SM2withSM3SignDer, SM2withSM3VerifyDer

test_data_1: dict = {
    "plain_text": "hello",
    "public_key": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "public_key_hex_128": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "public_key_hex_130": "04439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "public_key_der_base64": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQ5qZMsL/ljMJE7JcVmOHIezoe4cqkrLeJtxYRPS8RK3DPgXr18mDBk7/rgRdeLFcHEUc9h1RBFdGKsv0Vc5c9A==",
    "public_key_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "private_key": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}

class TestDerIBase(unittest.TestCase):

    def test_data_1(self):
        """ 测试SM2withSM3签名 """
        signed_text = SM2withSM3SignDer(
            test_data_1["private_key"],
            test_data_1["public_key"]).sign(
                test_data_1["plain_text"],
                asn1_der=True
            )
        verify_flag1: bool = SM2withSM3VerifyDer().verify(
            plain_text=test_data_1["plain_text"],
            signed_text = signed_text,
            public_key = test_data_1["public_key_hex_128"],
            asn1_der=True
        )
        verify_flag2: bool = SM2withSM3VerifyDer().verify(
            plain_text=test_data_1["plain_text"],
            signed_text = signed_text,
            public_key = test_data_1["public_key_hex_130"],
            asn1_der=True
        )
        verify_flag3: bool = SM2withSM3VerifyDer().verify(
            plain_text=test_data_1["plain_text"],
            signed_text = signed_text,
            public_key = test_data_1["public_key_der_base64"],
            asn1_der=True
        )
        verify_flag4: bool = SM2withSM3VerifyDer().verify(
            plain_text=test_data_1["plain_text"],
            signed_text = signed_text,
            public_key = test_data_1["public_key_der_hex"],
            asn1_der=True
        )
        self.assertTrue(verify_flag1 and verify_flag2 and verify_flag3 and verify_flag4)

if __name__ == "__main__":
    unittest.main()