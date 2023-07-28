import unittest, sys
sys.path.append('.')

from Pubkey import SM2Pubkey, SM2PubkeyProcess

class TestDerIBase(unittest.TestCase):

    def test_sm2_pubkey_process(self):
        """ 测试SM2公钥值转换数据 """
        # 测试SM2公钥值转换数据 
        data: dict = {
            "input_string_1": "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "input_string_2": "046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "input_string_3": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEaoJueQMrphRPoesi9PK6PSt369xUeJwe8Vtk+8/nolnncd3S/m3bN3samCCzlPWK+ivwIibsXa76zBSyoi1OEQ==",
            "base64_der": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEaoJueQMrphRPoesi9PK6PSt369xUeJwe8Vtk+8/nolnncd3S/m3bN3samCCzlPWK+ivwIibsXa76zBSyoi1OEQ==",
            "hex_raw": "6A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        }
        # 开始测试
        ## input_string_1
        sm2_pubkey: SM2Pubkey = SM2PubkeyProcess(data["input_string_1"]).sm2_pubkey
        self.assertEqual(sm2_pubkey.base64_der, data["base64_der"])
        self.assertEqual(sm2_pubkey.hex_raw, data["hex_raw"].lower())
        ## input_string_2
        sm2_pubkey: SM2Pubkey = SM2PubkeyProcess(data["input_string_2"]).sm2_pubkey
        self.assertEqual(sm2_pubkey.base64_der, data["base64_der"])
        self.assertEqual(sm2_pubkey.hex_raw, data["hex_raw"])
        ## input_string_3
        sm2_pubkey: SM2Pubkey = SM2PubkeyProcess(data["input_string_3"]).sm2_pubkey
        self.assertEqual(sm2_pubkey.base64_der, data["base64_der"])
        self.assertEqual(sm2_pubkey.hex_raw, data["hex_raw"].lower())

if __name__ == "__main__":
    unittest.main()