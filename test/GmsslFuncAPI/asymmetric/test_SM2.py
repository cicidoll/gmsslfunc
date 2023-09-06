from typing import Dict
import unittest, sys
sys.path.append('.')

from GmsslFuncAPI.asymmetric.SM2 import SM2AsymmetricAPI
from GmsslFuncAPI.asymmetric.Enums import ReturnsData
from utils.StringConvert import StringConvert

sm2_key: Dict[str, str] = {
    "pk": "08F83B4270A87139B4F295245D80E377684F8FB4B108DE5D03D088FAE67CCC4AA9C1477E3A6768CC2354479CC4ECE6ADB5E80F019E3D236C6C5BE17B05152644",
    "sk": "4E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443E"
}

class TestSM2AsymmetricAPI(unittest.TestCase):

    def test_encrypt(self):
        """ 测试SM2加密 """

        # 测试返回成功-code=0
        encrypted_response: str = SM2AsymmetricAPI.encrypt(
            plain_text = StringConvert.str_convert_base64("hello"),
            public_key = sm2_key["pk"],
            asn1_der = True
        )
        self.assertTrue(encrypted_response["code"]==0)
        # 测试传入plain_text格式不为base64
        encrypted_response: str = SM2AsymmetricAPI.encrypt(
            plain_text = "hello",
            public_key = sm2_key["pk"],
            asn1_der = True
        )
        self.assertTrue(encrypted_response["code"]==23186)
        # 测试传入public_key格式错误
        plain_text: str = "hello"
        encrypted_response: str = SM2AsymmetricAPI.encrypt(
            plain_text = plain_text,
            public_key = "error",
            asn1_der = True
        )
        self.assertTrue(encrypted_response["code"]==23186)

    def test_decrypt(self):
        """ 测试SM2解密 """

        # 获取加密值
        encrypted_data: str = SM2AsymmetricAPI.encrypt(
            plain_text = StringConvert.str_convert_base64("hello"),
            public_key = sm2_key["pk"],
            asn1_der = True
        )["data"][ReturnsData.ENCRYPT.value]

        # 测试成功-code=0
        plain_text_response: str = SM2AsymmetricAPI.decrypt(
            private_key = sm2_key["sk"],
            encrypted_data = encrypted_data,
            asn1_der = True
        )
        self.assertTrue(plain_text_response["code"]==0)

        # 测试传入private_key格式错误-code=23186
        plain_text_response: str = SM2AsymmetricAPI.decrypt(
            private_key = "error",
            encrypted_data = encrypted_data,
            asn1_der = True
        )
        self.assertTrue(plain_text_response["code"]==23186)

        # 测试传入encrypted_data格式错误-code=23186
        plain_text_response: str = SM2AsymmetricAPI.decrypt(
            private_key = sm2_key["sk"],
            encrypted_data = StringConvert.base64_convert_hex(encrypted_data),
            asn1_der = True
        )
        self.assertTrue(plain_text_response["code"]==23186)

        # 测试传入encrypted_data值错误-code=23222
        plain_text_response: str = SM2AsymmetricAPI.decrypt(
            private_key = sm2_key["sk"],
            encrypted_data = StringConvert.str_convert_base64("error"),
            asn1_der = True
        )
        self.assertTrue(plain_text_response["code"]==23222)

if __name__ == "__main__":
    unittest.main()