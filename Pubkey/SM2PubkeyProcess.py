from collections import Counter
from typing import List
# 导入自定义类
from utils.StringConvert import StringConvert
from ASN1Der.Object import ASN1DerToRawObject
from ASN1Der.Factory import ASN1DerToRaw
from .Error import PubkeyProcessCode, PubkeyProcessError
from .SM2Pubkey import SM2Pubkey

class SM2PubkeyProcess:
    """ 转换公钥主流程 """
    # 载入用户输入的公钥编码类型信息
    sm2_pubkey: SM2Pubkey = SM2Pubkey()
    _string_type: str # 输入值的编码类型
    _pubkey_type: str # 输入值的公钥类型

    def __init__(self, value: str) -> None:
        self.main(value)
        
    def main(self, value: str) -> None:
        """ 启动主流程 """
        self._select_process(value)
    
    def _select_process(self, value: str) -> None:
        """ 进入转换流程 """
        # 获得输入的公钥值
        input_string: str = self._process_input_string(value)
        # 开始转换
        if self._pubkey_type == "Raw":
            self.sm2_pubkey.hex_raw = input_string
            self.sm2_pubkey.base64_der = StringConvert.hex_convert_base64(self._hex_raw_convert_der(input_string))
        elif self._pubkey_type == "Der":
            self.sm2_pubkey.hex_raw = self._hex_der_convert_raw(input_string)[-128:]
            self.sm2_pubkey.base64_der = StringConvert.hex_convert_base64(input_string)

    def _process_input_string(self, value: str) -> None:
        """ 处理输入内容为可处理格式-自动检测格式 """
        input_string: str = value
        # 1、检查编码类型
        if not StringConvert.is_base64(input_string) and not StringConvert.is_hex(input_string):
            raise PubkeyProcessError(PubkeyProcessCode.StringTypeError) # 抛出编码类型报错
        self.string_type = "Base64" if StringConvert.is_base64(input_string) else "Hex"
        # 2、检查格式类型
        # Base64编码统一处理为十六进制
        input_string = StringConvert.base64_convert_hex(input_string) if self.string_type == "Base64" else input_string
        if len(input_string) == 130 or len(input_string) == 128:
            # 若为Hex编码130长度带公钥标识，处理为128长度Hex编码Raw格式公钥
            input_string = input_string[-128:]
            self._pubkey_type = "Raw" # 确定公钥值类型为Raw格式
        elif len(input_string) > 130:
            # 检测是否为Der格式公钥：根据整值进行Der对象实例化
            is_der_result: bool = self._is_hex_der_pubkey(input_string)
            if is_der_result == False:
                raise PubkeyProcessError(PubkeyProcessCode.PubkeyTypeError) # 抛出公钥类型报错
            else:
                self._pubkey_type = "Der" # 确定公钥值类型为Der格式
        else:
            raise PubkeyProcessError(PubkeyProcessCode.PubkeyTypeError) # 抛出公钥类型报错
        return input_string

    def _is_hex_der_pubkey(self, input_string: str) -> bool:
        """ 检测是否为der格式公钥 """
        assert_result: list = [ASN1DerToRawObject.Oid, ASN1DerToRawObject.Oid, ASN1DerToRawObject.BitString]
        der_objects_list: List[ASN1DerToRawObject.DerToRawIBase] = ASN1DerToRaw.DerObjectsSplit(input_string).der_objects_list
        diff_add_list: list = [ i.__class__ for i in der_objects_list if i.__class__ in assert_result]
        # Der格式公钥会解析出来两个Oid和一个BIT STRING
        return True if Counter(diff_add_list) == Counter(assert_result) else False
    
    def _hex_raw_convert_der(self, pubkey: str) -> str:
        """ 十六进制128长度公钥-Raw格式转换为Der格式 """
        pubkey = "03420004" + pubkey
        # OID对象标识符-固定值
        oid: str = "301306072A8648CE3D020106082A811CCF5501822D"
        result: str = "30" + str(hex(int(len(oid + pubkey) / 2))[2:]) + oid + pubkey
        return result
    
    def _hex_der_convert_raw(self, input_string: str) -> str:
        """ 十六进制Der格式公钥-Der格式转换为Raw格式 """
        der_objects_list: List[ASN1DerToRawObject.DerToRawIBase] = ASN1DerToRaw.DerObjectsSplit(input_string).der_objects_list
        pubkey_der_object: ASN1DerToRawObject.BitString = [i for i in der_objects_list if i.__class__ == ASN1DerToRawObject.BitString][0]
        return pubkey_der_object.value