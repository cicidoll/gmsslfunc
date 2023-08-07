from typing import List
# 导入自定义库
from ASN1Der import ASN1DerObjectTagsEnum
from SM2Key.SM2KeyCreate import calculate_public_key
from SM2Key.PrivateKey import SM2PrivateKeyProcess, SM2PrivateKey
from SM2Key.Pubkey import SM2PubkeyProcess, SM2Pubkey
from ASN1Der.Factory import RawToASN1DerObjectFactory, DerObjectsSplit
from ASN1Der.Object.RawToASN1DerObject import Sequence as RawToASN1DerSequence
from ASN1Der.Object.ASN1DerToRawObject import INTEGER as ASN1DerToRawINTEGER
from ASN1Der.Object import DerObjectIBase
from utils.StringConvert import StringConvert
from .sm2withsm3 import SM2withSM3Sign, SM2withSM3Verify

class SM2withSM3SignDer:

    def __init__(self, private_key: str, public_key: str = "") -> None:
        self.private_key: SM2PrivateKey = SM2PrivateKeyProcess(private_key).private_key_der
        self.public_key: SM2Pubkey = SM2PubkeyProcess(public_key).pubkey_der if public_key != "" else SM2PubkeyProcess(calculate_public_key(private_key)).pubkey_der
        self.sm2_with_sm3_sign: SM2withSM3Sign = SM2withSM3Sign(
            self.private_key.get_hex_raw(),
            self.public_key.get_hex_raw_128()
        )

    def sign(self, msg: str, userid: str = "1234567812345678", asn1_der: bool = False) -> str:
        """ SM2withSM3签名
            :params msg utf-8编码原文
            :params userid 使用默认1234567812345678 
            :params asn1_der 是否输出Der格式Base64编码签名
            :return 字符串类型 当asn1_der为True时，返回Der格式Base64编码签名值；当asn1_der为False时，返回Raw格式Hex编码128长度的签名值
        """
        signed_data: str = self.sm2_with_sm3_sign.sign(msg, userid)
        if asn1_der == False:
            return "%s" % signed_data
        else:
            result: RawToASN1DerSequence = RawToASN1DerObjectFactory.create_sequence_object(
                # 将R S转换为Der对象
                RawToASN1DerObjectFactory.create_der_object(signed_data[:64], ASN1DerObjectTagsEnum.INTEGER.value),
                RawToASN1DerObjectFactory.create_der_object(signed_data[64:], ASN1DerObjectTagsEnum.INTEGER.value)
            ).get_base64_der()
            return result
        

class SM2withSM3VerifyDer:

    def verify(self, plain_text: str, signed_text: str, public_key: str, userid: str = "1234567812345678", asn1_der: bool = False) -> bool:
        """ 验证Raw格式SM2withSM3裸签名
            :params plain_text utf-8编码原文
            :params signed_text 签名值 当asn1_der为True时，输入Der格式Base64编码签名值；当asn1_der为False时，输入Raw格式Hex编码128长度的签名值
            :params public_key Hex编码128/130长度公钥 Base64编码Der格式公钥 都支持
            :params userid 使用默认1234567812345678 
            :params asn1_der 是否输入Der格式Base64编码签名
            :return 布尔类型 验签结果
        """
        if asn1_der == True:
            signed_text_der_list: List[DerObjectIBase] = DerObjectsSplit(StringConvert.base64_convert_hex(signed_text)).der_objects_list
            [R, S] = [ i.get_hex_raw() for i in signed_text_der_list if isinstance(i, ASN1DerToRawINTEGER) ]
            signed_text = "%s%s" % (R, S)
        public_key: SM2Pubkey = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128()
        return SM2withSM3Verify().verify(plain_text, signed_text, public_key, userid)