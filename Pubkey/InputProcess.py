from enum import Enum
from collections import Counter
from typing import List
from StringConvert import StringConvert
from MyError import PubkeyProcessCode, PubkeyProcessError
from Pubkey import SM2Pubkey
import ASN1Der

class StringTypeDescriptionEnum(Enum):
    """ 字符串编码类型描述枚举 """
    Base64: str = "Base64"
    Hex: str = "Hex"

class PubkeyTypeDescriptionEnum(Enum):
    """ 公钥类型描述枚举 """
    Raw: str = "Raw"
    Der: str = "Der"

class TypeMatch:

    @classmethod
    def string_type_match(cls, type: int) -> Enum:
        # 0为Base64编码, 1为Hex编码
        match type:
            case 0:
                return StringTypeDescriptionEnum.Base64
            case 1:
                return StringTypeDescriptionEnum.Hex
            case _:
                raise PubkeyProcessError(PubkeyProcessCode.ErrorCode) # 抛出通用异常

    @classmethod
    def pubkey_type_match(cls, type: int) -> Enum:
        # 0为Raw格式, 1为Der格式
        match type:
            case 0:
                return PubkeyTypeDescriptionEnum.Raw
            case 1:
                return PubkeyTypeDescriptionEnum.Der
            case _:
                raise PubkeyProcessError(PubkeyProcessCode.ErrorCode) # 抛出通用异常

class SM2PubkeyInfo:
    """ 获得用户输入的编码类型信息 """

    def __init__(self) -> None:
        self.pubkey: SM2Pubkey = SM2Pubkey()
        self.__string_type: Enum # 标识字符串编码类型
        self.__pubkey_type: Enum # 标识公钥类型

    @property
    def string_type(self) -> Enum:
        return self.__string_type

    @string_type.setter
    def string_type(self, value: int):
        self.__string_type = TypeMatch.string_type_match(value)

    @property
    def pubkey_type(self) -> Enum:
        return self.__pubkey_type

    @pubkey_type.setter
    def pubkey_type(self, value: int):
        self.__pubkey_type = TypeMatch.pubkey_type_match(value)

class InputProcess:
    """ 转换公钥主流程 """
    # 载入用户输入的公钥编码类型信息
    sm2_pubkey_info: SM2PubkeyInfo = SM2PubkeyInfo()

    def __init__(self) -> None:
        self.main()
        
    def main(self) -> None:
        """ 启动主流程 """
        self._select_process()
    
    def _select_process(self) -> None:
        """ 进入转换流程 """
        # 获得输入的公钥值
        input_string: str = self._process_input_string()
        # 开始转换
        if self.sm2_pubkey_info.pubkey_type.name == "Raw":
            self.sm2_pubkey_info.pubkey.hex_raw = input_string
            self.sm2_pubkey_info.pubkey.base64_der = StringConvert.hex_convert_base64(self._hex_raw_convert_der(input_string))
        
        elif self.sm2_pubkey_info.pubkey_type.name == "Der":
            self.sm2_pubkey_info.pubkey.hex_raw = self._hex_der_convert_raw(input_string)
            self.sm2_pubkey_info.pubkey.base64_der = StringConvert.hex_convert_base64(input_string)

    def _process_input_string(self) -> None:
        """ 处理输入内容为可处理格式-自动检测格式 """
        print("请输入需要转换的公钥值（自动检测编码类型及格式）：")
        input_string: str = input()

        # 1、检查编码类型
        if not StringConvert.is_base64(input_string) and not StringConvert.is_hex(input_string):
            raise PubkeyProcessError(PubkeyProcessCode.StringTypeError) # 抛出编码类型报错
        self.sm2_pubkey_info.string_type = 0 if StringConvert.is_base64(input_string) else 1
        
        # 2、检查格式类型
        # Base64编码统一处理为十六进制
        input_string = StringConvert.base64_convert_hex(input_string) if self.sm2_pubkey_info.string_type.name == "Base64" else input_string

        if len(input_string) == 130 or len(input_string) == 128:
            # 若为Hex编码130长度带公钥标识，处理为128长度Hex编码Raw格式公钥
            input_string = input_string[-128:]
            self.sm2_pubkey_info.pubkey_type = 0 # 确定公钥值类型为Raw格式
        elif len(input_string) > 130:
            # 检测是否为Der格式公钥：根据整值进行Der对象实例化
            is_der_result: bool = self._is_hex_der_pubkey(input_string)
            
            if is_der_result == False:
                raise PubkeyProcessError(PubkeyProcessCode.PubkeyTypeError) # 抛出公钥类型报错
            else:
                self.sm2_pubkey_info.pubkey_type = 1 # 确定公钥值类型为Der格式
        else:
            raise PubkeyProcessError(PubkeyProcessCode.PubkeyTypeError) # 抛出公钥类型报错
        return input_string

    def _is_hex_der_pubkey(self, input_string: str) -> bool:
        """ 检测是否为der格式公钥 """
        assert_result: list = [ASN1Der.Oid, ASN1Der.Oid, ASN1Der.BitString]
        der_objects_list: List[ASN1Der.DerIBase] = ASN1Der.DerObjects(input_string).der_objects_list
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
        der_objects_list: List[ASN1Der.DerIBase] = ASN1Der.DerObjects(input_string).der_objects_list
        pubkey_der_object: ASN1Der.BitString = [i for i in der_objects_list if i.__class__ == ASN1Der.BitString][0]
        return pubkey_der_object.value