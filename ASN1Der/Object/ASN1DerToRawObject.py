from enum import Enum
# 导入自定义库
from utils.StringConvert import StringConvert
from ..Error import ASN1DerProcessCode, ASN1DerProcessError
from ..TagsEnum import ASN1DerObjectTagsEnum

class DerToRawIBase:
    """ 遵循TLV格式的ASN1.Der编码规则: 将Der格式的String实例化为Der对象 """

    def __init__(self, value: str) -> None:
        """ 初始化的value值需为十六进制 """
        # 定义实例属性
        self.tag: str # Tag字段，代表类型
        self.length: str # Length字段，代表长度，十六进制
        self.value: str # Value字段，代表实际值，十六进制
        # 启动主线程
        try:
            self.main(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
        
    def main(self, value: str) -> None:
        """ 主线程 """
        # 输入值编码检测及赋值
        self._process_string_type(value)
        self._value: str = value
        # 处理Tag字段
        self.tag = self._value[:2]
        # 处理Length字段及Value字段长度检测
        value_len: int = self._calculation_length() # Value字段占用的字节数
        self._process_value(value_len)

    def _calculation_length(self) -> int:
        """ 计算长度 """
        first: str = self._value[2:4] # Length字段的第一个字节
        flag: bool = True if StringConvert.hex_convert_bin(first)[0] == "0" else False # 判断第一个字段的位7是否为0
        # 开始计算实际Length字段
        if flag:
            value_len: int = StringConvert.hex_convert_int(first)
            self.length = first # 赋值Length字段
        else:
            num_len: int = StringConvert.bin_convert_int("0" + StringConvert.hex_convert_bin(first)[1:]) # 计算得到Length字段占用字节长度
            value_len: int = StringConvert.hex_convert_int(self._value[4: 4+num_len*2])
            self.length = self._value[2: 4+num_len*2] # 赋值Length字段
        # 返回Value字段实际长度
        return value_len
    
    def _process_value(self, value_len: int) -> None:
        """ 处理Value字段 """
        if len(self._value[2+len(self.length):]) != 2 * value_len:
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
        # 处理Value字段
        self.value = self._value[2+len(self.length):]

    def _process_string_type(self, value: str):
        """ 输入值编码检测 """
        if StringConvert.is_base64(value) or not StringConvert.is_hex(value):
            raise ASN1DerProcessError(ASN1DerProcessCode.StringTypeError) # 抛出编码异常

    def _is_tag(self, tag: str) -> None:
        """ Tag字段检测 """
        if self.tag != tag:
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常

class Sequence(DerToRawIBase):
    """ Sequence-序列类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # Sequence类型Tag为30
        self._is_tag(ASN1DerObjectTagsEnum.Sequence.value)

class Oid(DerToRawIBase):
    """ OID-对象标识符类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # OID类型Tag为06
        self._is_tag(ASN1DerObjectTagsEnum.Oid.value)

class INTEGER(DerToRawIBase):
    """ INTEGER-整数值类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # INTEGER类型Tag为02
        self._is_tag(ASN1DerObjectTagsEnum.INTEGER.value)
        self._process_integer_value()

    def _process_integer_value(self) -> None:
        """ 处理Value字段-处理前导字节0x00 """
        first_one_byte: str = self.value[:2]
        # 处理Value字段
        if first_one_byte == "00":
            value = self.value[2:]
            if bin(int(value, base=16)).replace("0b", "")[0] != "1":
                raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
            self.value = value

class BitString(DerToRawIBase):
    """ BIT STRING类型 """

    def __init__(self, value: str) -> None:
        super().__init__(value)
        # BIT STRING类型Tag为03
        self._is_tag(ASN1DerObjectTagsEnum.BitString.value)
        # 处理Value字段的前导字节
        self._process_bitstring_value()

    def _process_bitstring_value(self) -> None:
        """ 处理Value字段的前导字节 """
        unused_num: int = StringConvert.hex_convert_int(self.value[:2])
        bin_value: str = StringConvert.hex_convert_bin(self.value[2:])
        self.value =  StringConvert.bin_convert_hex(bin_value[:len(bin_value)-unused_num] + unused_num * "0")

class ASN1DerToRawObjectsEnum(Enum):
    """ ASN1DerToRaw对象类型枚举 """
    Sequence: Sequence = Sequence # Sequence-序列类型
    Oid: Oid = Oid # OID-对象标识符类型
    BitString: BitString = BitString # BIT STRING类型
    INTEGER: INTEGER = INTEGER # INTEGER类型