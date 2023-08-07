from typing import Dict
import unittest, sys
sys.path.append('.')

from SM2Key.PrivateKey import PrivateKeyDer

class TestPubkeyDer(unittest.TestCase):

    def test_private_key_GMT00102012_der_instance(self):
        """ 测试SM2私钥值转换数据 """
        # 测试SM2私钥值转换数据 
        test_data: Dict[str, str] = {
            # 测试输入
            "input_string_1": "4E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443E",
            "input_string_2": "307702010104204E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443EA00A06082A811CCF5501822DA1440342000408F83B4270A87139B4F295245D80E377684F8FB4B108DE5D03D088FAE67CCC4AA9C1477E3A6768CC2354479CC4ECE6ADB5E80F019E3D236C6C5BE17B05152644",
            "input_string_3": "MHcCAQEEIE4t/EJzJmbiHClSyEJBkPYf7aKjhNLNsYzRMndGLUQ+oAoGCCqBHM9VAYItoUQDQgAECPg7QnCocTm08pUkXYDjd2hPj7SxCN5dA9CI+uZ8zEqpwUd+OmdozCNUR5zE7OattegPAZ49I2xsW+F7BRUmRA==",
            # 测试结果
            "hex_raw": "4E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443E",
            "hex_der": "307702010104204E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443EA00A06082A811CCF5501822DA1440342000408F83B4270A87139B4F295245D80E377684F8FB4B108DE5D03D088FAE67CCC4AA9C1477E3A6768CC2354479CC4ECE6ADB5E80F019E3D236C6C5BE17B05152644",
            "base64_der": "MHcCAQEEIE4t/EJzJmbiHClSyEJBkPYf7aKjhNLNsYzRMndGLUQ+oAoGCCqBHM9VAYItoUQDQgAECPg7QnCocTm08pUkXYDjd2hPj7SxCN5dA9CI+uZ8zEqpwUd+OmdozCNUR5zE7OattegPAZ49I2xsW+F7BRUmRA=="
        }
        # 开始测试
        ## input_string_1
        sm2_privatekey_1: PrivateKeyDer.PrivateKeyDerGMT00102012 = PrivateKeyDer.PrivateKeyDerGMT00102012Factory.create_Raw2Der_PrivateKeyDer(test_data["input_string_1"])
        self.assertEqual(sm2_privatekey_1.get_hex_raw().lower(), test_data["hex_raw"].lower())
        self.assertEqual(sm2_privatekey_1.get_hex_der().lower(), test_data["hex_der"].lower())
        self.assertEqual(sm2_privatekey_1.get_base64_der(), test_data["base64_der"])
        ## input_string_2
        sm2_privatekey_2: PrivateKeyDer.PrivateKeyDerGMT00102012 = PrivateKeyDer.PrivateKeyDerGMT00102012Factory.create_Der2Raw_PrivateKeyDer(test_data["input_string_2"])
        self.assertEqual(sm2_privatekey_2.get_hex_raw().lower(), test_data["hex_raw"].lower())
        self.assertEqual(sm2_privatekey_2.get_hex_der().lower(), test_data["hex_der"].lower())
        self.assertEqual(sm2_privatekey_2.get_base64_der(), test_data["base64_der"])
        self.assertTrue(PrivateKeyDer.PrivateKeyDerGMT00102012Factory.is_hex_der_private_key(test_data["input_string_2"]))
        ## input_string_3
        sm2_privatekey_3: PrivateKeyDer.PrivateKeyDerGMT00102012 = PrivateKeyDer.PrivateKeyDerGMT00102012Factory.create_Der2Raw_PrivateKeyDer(test_data["input_string_3"])
        self.assertEqual(sm2_privatekey_3.get_hex_raw().lower(), test_data["hex_raw"].lower())
        self.assertEqual(sm2_privatekey_3.get_hex_der().lower(), test_data["hex_der"].lower())
        self.assertEqual(sm2_privatekey_3.get_base64_der(), test_data["base64_der"])
        self.assertTrue(PrivateKeyDer.PrivateKeyDerGMT00102012Factory.is_hex_der_private_key(test_data["input_string_2"]))

if __name__ == "__main__":
    unittest.main()