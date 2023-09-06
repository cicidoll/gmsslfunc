from operator import xor
from typing import Dict, Any
# 导入底层方法
from Asymmetric.SM2Der import SM2AsymmetricDer
from .Enums import ReturnsData, Returns
# 导入检测所需函数
from utils import StringConvert
from SM2Key.PrivateKey import SM2PrivateKeyProcess
from SM2Key.Pubkey import SM2PubkeyProcess


class SM2AsymmetricAPI:
    """ SM2非对称加解密-SM2-本地实现-API接口 """

    @staticmethod
    def encrypt(plain_text: str, public_key: str, asn1_der: bool) -> Dict[str, Any]:
        """
            SM2非对称加密算法-本地实现-API接口

            :params plain_text utf-8字符集 Base64编码原文
            :params public_key 支持: 128长度Raw格式Hex编码公钥/130长度Raw格式Hex编码公钥/Der格式Base64编码公钥/Der格式Hex编码公钥
            :params asn1_der True: 输出Der格式Base64编码加密值; False: 输出Raw格式Hex编码加密值
            :returns: String类型 C1C3C2
        """
        returns: dict = Returns.SUCCESS.value # 返回码Code Msg信息
        data_key: dict = ReturnsData.ENCRYPT.value # 返回值-键名
        encrypted_data: str = ""
        # 1、检测密钥格式
        try:
            public_key: str = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128()
        except Exception:
            returns = Returns.INPUT_ERROR.value # 入参格式错误
        # 2、检查原文格式
        returns = returns if StringConvert.is_base64(plain_text) else Returns.INPUT_ERROR.value
        # 3、若入参格式错误，直接返回报错
        if returns != Returns.SUCCESS.value:
            return {**returns, "data": {data_key: None}}
        # 4、入参格式正确，开始调用函数
        try:
            encrypted_data = SM2AsymmetricDer().encrypt(
                plain_text = plain_text,
                public_key = public_key,
                asn1_der = asn1_der
            )
        except Exception:
            returns = Returns.HANDLE_ERROR.value
        # 5、返回API调用结果
        return {**returns, "data": {data_key: encrypted_data}}
    

    @staticmethod
    def decrypt(private_key: str, encrypted_data: str, asn1_der = bool) -> Dict[str, Any]:
        """
            SM2非对称解密算法-本地实现-API接口
            
            :params private_key 支持: 64长度Raw格式Hex编码SM2私钥 || Der格式Base64编码SM2私钥
            :params encrypted_data utf-8字符集 C1C3C2排列
            :params asn1_der True: 输入Der格式Base64编码加密值; False: 输入Raw格式Hex编码加密值
            :returns: String类型-原文 Base64编码
        """
        returns: dict = Returns.SUCCESS.value # 返回码Code Msg信息
        data_key: dict = ReturnsData.DECRYPT.value # 返回值-键名
        plain_text_data: str = "" # 解密后原文值
        # 1、检测公钥格式
        try:
            private_key: str = SM2PrivateKeyProcess(private_key).private_key_der.get_hex_raw()
        except Exception:
            returns = Returns.INPUT_ERROR.value # 入参格式错误
        # 2、检测密文格式
        returns = returns if StringConvert.is_base64(encrypted_data) and not xor(asn1_der, StringConvert.is_base64(encrypted_data)) else Returns.INPUT_ERROR.value
        # 3、若入参格式错误，直接返回报错
        if returns != Returns.SUCCESS.value: return {**returns, data_key: None}
        # 4、入参格式正确，开始调用函数
        try:
            plain_text_data: str = SM2AsymmetricDer().decrypt(
                private_key = private_key,
                encrypted_data = encrypted_data,
                asn1_der = asn1_der
            )
        except Exception:
            returns = Returns.HANDLE_ERROR.value
        return {**returns, "data": plain_text_data}