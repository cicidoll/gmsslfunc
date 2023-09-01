from operator import xor
from typing import Dict, Any
# 导入底层方法
from ...Sign import SM2withSM3SignDer, SM2withSM3VerifyDer
from .Enums import ReturnsData, Returns
# 导入检测所需函数
from ...utils import StringConvert
from ...SM2Key.PrivateKey import SM2PrivateKeyProcess
from ...SM2Key.Pubkey import SM2PubkeyProcess
from ...SM2Key.SM2KeyCreate import calculate_public_key


class RawAPI:
    """ 国密算法-编制/核验裸签名-SM2withSM3-本地实现-API接口 """

    @staticmethod
    def sign(private_key: str, public_key: str, plain_text: str, userid: str, asn1_der: bool) -> Dict[str, Any]:
        """
            国密算法-编制Raw签名-SM2withSM3签名-本地实现-API接口

            :params private_key 私钥 支持Hex编码Raw格式/Base64编码Der格式
            :params public_key 公钥 支持Hex编码Raw格式/Base64编码Der格式
            :params plain_text 原文 utf-8字符集-Base64编码
            :params userid 使用规范中的默认值 "1234567812345678"
            :params asn1_der 是否输出Der格式Base64编码签名
            :return: 签名结果 True:返回Der格式Base64编码签名值; False:返回Raw格式Hex编码128长度的签名值
        """
        returns: dict = Returns.SUCCESS.value # 返回码Code Msg信息
        data_key: dict = ReturnsData.SIGN.value # 返回值-键名
        result: str = "" # 签名值
        # 1、检测密钥格式
        try:
            private_key: str = SM2PrivateKeyProcess(private_key).private_key_der.get_hex_raw()
            public_key: str = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128()
            ## 检查公私钥是否配套
            if calculate_public_key(private_key).upper() != public_key.upper(): returns = Returns.INPUT_ERROR.value
        except Exception:
            returns = Returns.INPUT_ERROR.value # 入参格式错误
        # 2、检查原文格式
        returns = returns if StringConvert.is_base64(plain_text) else Returns.INPUT_ERROR.value
        # 3、若入参格式错误，直接返回报错
        if returns != Returns.SUCCESS.value:
            return {**returns, "data": {data_key: None}}
        # 4、入参格式正确，开始调用函数
        try:
            result = SM2withSM3SignDer(private_key, public_key).sign(
                plain_text = plain_text,
                userid = userid,
                asn1_der = asn1_der
            )
        except Exception:
            returns = Returns.HANDLE_ERROR.value
        # 5、返回API调用结果
        return {**returns, "data": {data_key: result}}
    

    @staticmethod
    def verify(plain_text: str, signed_text: str, public_key: str, userid: str, asn1_der: bool) -> Dict[str, Any]:
        """
            国密算法-核验Raw裸签名-SM2withSM3-本地实现-API接口

            :params plain_text 原文 utf-8字符集 Base64编码
            :params signed_text 签名值 True: 输入Der格式Base64编码签名值; False: 输入Raw格式Hex编码128长度的签名值
            :params public_key Hex编码128/130长度公钥 Base64编码Der格式公钥 都支持
            :params userid 使用默认1234567812345678 
            :params asn1_der 是否输入Der格式Base64编码签名
            :return: 验签结果
        """
        returns: dict = Returns.SUCCESS.value # 返回码Code Msg信息
        data: dict = ReturnsData.VERIFY.value # 返回值-键名
        # 1、检测公钥格式
        try:
            public_key: str = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128()
        except Exception:
            returns = Returns.INPUT_ERROR.value # 入参格式错误
        # 2、检测原文和签名值格式
        returns = returns if StringConvert.is_base64(plain_text) and not xor(asn1_der, StringConvert.is_base64(signed_text)) else Returns.INPUT_ERROR.value
        # 3、若入参格式错误，直接返回报错
        if returns != Returns.SUCCESS.value: return {**returns, "data": data}
        # 4、入参格式正确，开始调用函数
        try:
            result: bool = SM2withSM3VerifyDer().verify(
                plain_text = plain_text,
                signed_text = signed_text,
                public_key = public_key,
                userid = userid,
                asn1_der = asn1_der
            )
        except Exception:
            returns = Returns.HANDLE_ERROR.value
        returns = Returns.VERIFY_ERROR.value if result == False else returns
        return {**returns, "data": data}