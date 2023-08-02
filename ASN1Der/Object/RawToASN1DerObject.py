from enum import Enum
# 导入自定义库
from utils.StringConvert import StringConvert
from .IBase import DerObjectIBase
from ..TagsEnum import ASN1DerObjectTagsEnum
from ..Error import ASN1DerProcessCode, ASN1DerProcessError

class RawToDerIBase(DerObjectIBase):
    """ 遵循TLV格式的ASN1.Der编码规则: 将String实例化为Der对象 """

    def __init__(self, value: str) -> None:
        """ 初始化的value值需为十六进制
            基类仅处理Length字段及常规Value字段
        """
        super().__init__(value)
        # 启动主线程
        try:
            self.main(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
        
    def main(self, value: str) -> None:
        """ 主线程 """
        self._process_string_type(value) # 编码检测
        self._process_value(value) # 根据不同类型处理Value值
        self._calculation_length() # 赋值Length字段

    def get_hex_der(self) -> str:
        """ 获取Hex编码的Der对象"""
        return self.tag + self.length + self.value

    def get_base64_der(self) -> str:
        """ 获取Base64编码的Der对象 """
        return StringConvert.hex_convert_base64(self.get_hex_der())

    def get_hex_raw(self) -> str:
        """ 获取Hex编码的Raw对象 """
        return self.hex_raw_value

    def _process_string_type(self, value: str):
        """ 输入值编码检测-需要为Hex编码 """
        if StringConvert.is_base64(value) or not StringConvert.is_hex(value):
            raise ASN1DerProcessError(ASN1DerProcessCode.StringTypeError) # 抛出编码异常

    def _process_value(self, value: str) -> None:
        """ 更新Value字段-self.hex_raw_value """
        self._input_value = value
        self.hex_raw_value = value
        self.value = value

    def _calculation_length(self) -> None:
        """ 计算长度 """
        value_len: int = int( len(self.value) / 2 )# 计算Value字段占用的字节数
        if value_len < 128:
            self.length = hex(value_len).replace("0x", "").zfill(2) # 用一个字节完成Length值
        elif value_len >= 128:
            length_value: str = StringConvert.int_convert_hex(value_len)
            length_flag: str = StringConvert.bin_convert_hex("1" + bin(int( len(length_value)/2 )).replace("0b", "").zfill(7))
            self.length = length_flag + length_value

    def _process_tag(self, value: str) -> None:
        """ 处理Tag字段 """
        self.tag = value

class Sequence(RawToDerIBase):
    """ Sequence-序列类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # Sequence类型Tag为30
        self._process_tag(ASN1DerObjectTagsEnum.Sequence.value)

class Oid(RawToDerIBase):
    """ OID-对象标识符类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # OID类型Tag为06
        self._process_tag(ASN1DerObjectTagsEnum.Oid.value)

class INTEGER(RawToDerIBase):
    """ INTEGER-整数值类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # INTEGER类型Tag为02
        self._process_tag(ASN1DerObjectTagsEnum.INTEGER.value)

    def _process_value(self, value: str) -> None:
        """ 处理Value字段-处理前导字节0x00 """
        self._input_value = value
        self.hex_raw_value = value
        self.value = "00" + value if StringConvert.hex_convert_bin(value)[0] == "1" else value

class BitString(RawToDerIBase):
    """ BIT STRING类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # BIT STRING类型Tag为03
        self._process_tag(ASN1DerObjectTagsEnum.BitString.value)

    def _process_value(self, value: str) -> None:
        """ 处理Value字段的前导字节 """
        self._input_value = value
        self.hex_raw_value = value
        self.value = "00" + value if len(value) % 2 == 0 else hex(4).replace("0x", "").zfill(2) + value + "0"

class RawToASN1DerObjectsEnum(Enum):
    """ RawToASN1Der对象类型枚举 """
    Sequence: Sequence = Sequence # Sequence-序列类型
    Oid: Oid = Oid # OID-对象标识符类型
    BitString: BitString = BitString # BIT STRING类型
    INTEGER: INTEGER = INTEGER # INTEGER类型