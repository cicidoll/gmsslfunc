from typing import List
# 导入自定义库
from ASN1Der import ASN1DerObjectTagsEnum
from SM2Key.PrivateKey import SM2PrivateKeyProcess, SM2PrivateKey
from SM2Key.Pubkey import SM2PubkeyProcess, SM2Pubkey
from ASN1Der.Factory import RawToASN1DerObjectFactory, DerObjectsSplit
from ASN1Der.Object.RawToASN1DerObject import Sequence as RawToASN1DerSequence
from ASN1Der.Object.ASN1DerToRawObject import INTEGER as ASN1DerToRawINTEGER
from ASN1Der.Object.ASN1DerToRawObject import OCTETSTRING as ASN1DerToRawOCTETSTRING
from ASN1Der.Object import DerObjectIBase
from utils.StringConvert import StringConvert
from .SM2 import SM2Asymmetric

class SM2AsymmetricDer:
    """ SM2非对称加解密-支持Der格式 """
    # 组合-SM2非对称加解密类
    sm2_asymmetric: SM2Asymmetric = SM2Asymmetric()

    def encrypt(self, plain_text: str, public_key: str, asn1_der: bool = False) -> str:
        """
            SM2非对称加密算法
            :params plain_text utf-8字符集 Base64编码原文
            :params public_key 支持: 128长度Raw格式Hex编码公钥/130长度Raw格式Hex编码公钥/Der格式Base64编码公钥/Der格式Hex编码公钥
            :params asn1_der True: 输出Der格式Base64编码加密值; False: 输出Raw格式Hex编码加密值
            :returns: String类型 C1C3C2
        """
        plain_text: str = StringConvert.base64_convert_hex(plain_text) # Base64编码转Hex编码
        public_key: str = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128() # 处理SM2公钥
        encrypted_data: str = self.sm2_asymmetric.encrypt(
            plain_text = plain_text,
            public_key = public_key
        )
        if asn1_der == False: return encrypted_data # 输出Raw格式Hex编码加密值
        # Raw格式密文值转Der格式处理
        C1 = encrypted_data[:128]
        C1X, C1Y = C1[:64], C1[64:]
        C3 = encrypted_data[128:192]
        C2 = encrypted_data[192:]
        encrypted_data: RawToASN1DerSequence = RawToASN1DerObjectFactory.create_sequence_object(
            # 将C1 C3 C2转换为Der对象
            RawToASN1DerObjectFactory.create_der_object(C1X, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C1Y, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C3, ASN1DerObjectTagsEnum.OCTETSTRING.value),
            RawToASN1DerObjectFactory.create_der_object(C2, ASN1DerObjectTagsEnum.OCTETSTRING.value),
        ).get_base64_der()
        return encrypted_data
    
    def decrypt(self, private_key: str, encrypted_data: str, asn1_der = bool) -> str:
        """
            SM2非对称解密算法
            :params private_key 支持: 64长度Raw格式Hex编码SM2私钥 || Der格式Base64编码SM2私钥
            :params encrypted_data utf-8字符集 C1C3C2排列
            :params asn1_der True: 输入Der格式Base64编码加密值; False: 输入Raw格式Hex编码加密值
            :returns: String类型-原文 Base64编码
        """
        private_key: str = SM2PrivateKeyProcess(private_key).private_key_der.get_hex_raw() # 处理SM2私钥
        # 处理encrypted_data
        if asn1_der == True:
            encrypted_data_der_list: List[DerObjectIBase] = DerObjectsSplit(StringConvert.base64_convert_hex(encrypted_data)).der_objects_list
            C1 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawINTEGER)])
            C3 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING) and len(i.get_hex_raw()) == 64])
            C2 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING) and i.get_hex_raw() != C3])
            encrypted_data: str = C1 + C3 +C2
        # 解密
        plain_text_data: str = self.sm2_asymmetric.decrypt(
            private_key=private_key, 
            encrypted_data=encrypted_data
        )
        return StringConvert.hex_convert_base64(plain_text_data)