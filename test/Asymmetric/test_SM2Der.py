from typing import Dict
import unittest, sys
sys.path.append('.')

from Asymmetric.SM2Der import SM2AsymmetricDer
from utils.StringConvert import StringConvert

sm2_key: Dict[str, str] = {
    "pk": "08F83B4270A87139B4F295245D80E377684F8FB4B108DE5D03D088FAE67CCC4AA9C1477E3A6768CC2354479CC4ECE6ADB5E80F019E3D236C6C5BE17B05152644",
    "sk": "4E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443E"
}
plain_text: str = "hello"

class TestSM2Asymmetric(unittest.TestCase):

    def test_encrypt_and_decrypt(self):
        """ 测试SM2公钥加密 """
        sm2_asymmetric_der: SM2AsymmetricDer = SM2AsymmetricDer()
        encrypted_data: str = sm2_asymmetric_der.encrypt(
            plain_text=StringConvert.str_convert_base64(plain_text),
            public_key=sm2_key["pk"],
            asn1_der=True
        )
        # print(encrypted_data)
        
        plain_text_data: str = sm2_asymmetric_der.decrypt(
            private_key=sm2_key["sk"], 
            encrypted_data=encrypted_data,
            asn1_der=True
        )
        self.assertTrue(StringConvert.hex_convert_str(StringConvert.base64_convert_hex(plain_text_data)) == plain_text)

if __name__ == "__main__":
    unittest.main()