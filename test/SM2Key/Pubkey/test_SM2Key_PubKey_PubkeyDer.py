import unittest, sys
sys.path.append('.')

from SM2Key.Pubkey.PubkeyDer import PubkeyDer, PubkeyDerFactory

class TestPubkeyDer(unittest.TestCase):

    def test_pubkey_der_instance(self):
        """ 测试SM2公钥值转换数据 """
        # 测试SM2公钥值转换数据 
        test_data: dict = {
            # 测试输入
            "input_string_1": "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "input_string_2": "6A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            # 测试结果
            "hex_raw_128": "6A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "hex_raw_130": "046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "hex_der": "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "base64_der": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEaoJueQMrphRPoesi9PK6PSt369xUeJwe8Vtk+8/nolnncd3S/m3bN3samCCzlPWK+ivwIibsXa76zBSyoi1OEQ=="
        }
        # 开始测试
        ## input_string_1
        sm2_pubkey_1: PubkeyDer = PubkeyDerFactory.create_Der2Raw_PubkeyDer(test_data["input_string_1"])
        self.assertEqual(sm2_pubkey_1.get_hex_raw_128().lower(), test_data["hex_raw_128"].lower())
        self.assertEqual(sm2_pubkey_1.get_hex_raw_130().lower(), test_data["hex_raw_130"].lower())
        self.assertEqual(sm2_pubkey_1.get_hex_der().lower(), test_data["hex_der"].lower())
        self.assertEqual(sm2_pubkey_1.get_base64_der(), test_data["base64_der"])
        ## input_string_2
        sm2_pubkey_2: PubkeyDer = PubkeyDerFactory.create_Raw2Der_PubkeyDer(test_data["input_string_2"])
        self.assertEqual(sm2_pubkey_2.get_hex_raw_128().lower(), test_data["hex_raw_128"].lower())
        self.assertEqual(sm2_pubkey_2.get_hex_raw_130().lower(), test_data["hex_raw_130"].lower())
        self.assertEqual(sm2_pubkey_2.get_hex_der().lower(), test_data["hex_der"].lower())
        self.assertEqual(sm2_pubkey_2.get_base64_der(), test_data["base64_der"])

if __name__ == "__main__":
    unittest.main()