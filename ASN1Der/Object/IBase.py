from abc import abstractmethod

class DerObjectIBase:
    """ 遵循TLV格式的ASN1.Der编码规则: Der对象基类 """
    
    def __init__(self, value: str) -> None:
        """ 初始化的value值需为十六进制 """
        # 定义实例属性
        self.tag: str # Tag字段，代表类型
        self.length: str # Length字段，代表长度，十六进制
        self.value: str # Value字段的值，十六进制
        self.hex_raw_value: str # 代表实际值，十六进制
        self._input_value: str # 原始输入Value值

    @abstractmethod
    def get_hex_der(self) -> str:
        """ 获取Hex编码的Der对象"""

    @abstractmethod
    def get_base64_der(self) -> str:
        """ 获取Base64编码的Der对象 """

    @abstractmethod
    def get_hex_raw(self) -> str:
        """ 获取Hex编码的Raw对象 """