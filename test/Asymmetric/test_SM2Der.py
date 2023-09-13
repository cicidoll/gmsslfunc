from typing import Dict
import unittest, sys
sys.path.append('.')

from Asymmetric.SM2Der import SM2AsymmetricDer, SM2AsymmetricEncryptedDataConvert
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
        # MG8CIQDmq/L4cbD8h9zxIiCAf1aKIzexMtVHEqFiy1GxLUEzBQIhAPHUby3ZxgxGXKrpWOzikkgKjb6LOzOXrgoGw8gx6glaBCAX/OsN1aKeAx94fRWR01KQEym9dPIxJ+2N3qaCMZAX5wQFRT5GWpY=
        
        plain_text_data: str = sm2_asymmetric_der.decrypt(
            private_key=sm2_key["sk"], 
            encrypted_data=encrypted_data,
            asn1_der=True
        )
        self.assertTrue(StringConvert.hex_convert_str(StringConvert.base64_convert_hex(plain_text_data)) == plain_text)

class TestSM2AsymmetricEncryptedDataConvert(unittest.TestCase):

    def test_SM2_encrypted_data_convert(self):
        """ 测试SM2非对称加密-密文值格式转换 """
        C1C3C2Der: str = "MG8CIQDmq/L4cbD8h9zxIiCAf1aKIzexMtVHEqFiy1GxLUEzBQIhAPHUby3ZxgxGXKrpWOzikkgKjb6LOzOXrgoGw8gx6glaBCAX/OsN1aKeAx94fRWR01KQEym9dPIxJ+2N3qaCMZAX5wQFRT5GWpY="
        C1C2C3Der: str = "MG8CIQDmq/L4cbD8h9zxIiCAf1aKIzexMtVHEqFiy1GxLUEzBQIhAPHUby3ZxgxGXKrpWOzikkgKjb6LOzOXrgoGw8gx6glaBAVFPkZalgQgF/zrDdWingMfeH0VkdNSkBMpvXTyMSftjd6mgjGQF+c="
        C1C3C2Raw: str = "04e6abf2f871b0fc87dcf12220807f568a2337b132d54712a162cb51b12d413305f1d46f2dd9c60c465caae958ece292480a8dbe8b3b3397ae0a06c3c831ea095a17fceb0dd5a29e031f787d1591d352901329bd74f23127ed8ddea682319017e7453e465a96"
        C1C2C3Raw: str = "04e6abf2f871b0fc87dcf12220807f568a2337b132d54712a162cb51b12d413305f1d46f2dd9c60c465caae958ece292480a8dbe8b3b3397ae0a06c3c831ea095a453e465a9617fceb0dd5a29e031f787d1591d352901329bd74f23127ed8ddea682319017e7"        

        self.assertTrue(C1C3C2Der == SM2AsymmetricEncryptedDataConvert.C1C2C3Der_to_C1C3C2Der(C1C2C3Der))
        self.assertTrue(C1C3C2Der == SM2AsymmetricEncryptedDataConvert.C1C3C2Raw_to_C1C3C2Der(C1C3C2Raw))
        self.assertTrue(C1C3C2Der == SM2AsymmetricEncryptedDataConvert.C1C2C3Raw_to_C1C3C2Der(C1C2C3Raw))
        self.assertTrue(C1C2C3Der == SM2AsymmetricEncryptedDataConvert.C1C2C3Raw_to_C1C2C3Der(C1C2C3Raw))
        self.assertTrue(C1C2C3Der == SM2AsymmetricEncryptedDataConvert.C1C3C2Raw_to_C1C2C3Der(C1C3C2Raw))
        self.assertTrue(C1C3C2Raw == SM2AsymmetricEncryptedDataConvert.C1C2C3Raw_to_C1C3C2Raw(C1C2C3Raw))

if __name__ == "__main__":
    unittest.main()