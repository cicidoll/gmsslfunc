from typing import List, Tuple
# 导入自定义库
from utils.StringConvert import StringConvert
from ..TagsEnum import ASN1DerObjectTagsEnum
from ..Error import ASN1DerProcessCode, ASN1DerProcessError
from ..Object import DerObjectIBase, ASN1DerToRawObjectsEnum

class ASN1DerObjectFactory:
    """ 创建ASN1.Der对象-工厂 """

    @staticmethod
    def create_der_object(value: str) -> DerObjectIBase:
        """ 创建对应的对象类型 """
        try:
            tag: str = value[:2]
            object_name: str = ASN1DerObjectTagsEnum(tag).name
            return ASN1DerToRawObjectsEnum[object_name].value(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
        
class DerObjectsSplit:
    """ 拆分Sequence类型整值内的多个Der对象 """

    def __init__(self, value: str) -> None:
        try:
            # 声明并赋值类属性
            self.der_objects_list: List[DerObjectIBase] = self._process_values(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常

    def _process_values(self, value: str) -> List[DerObjectIBase]:
        data_list: List[str] = [value]
        result_list: List[DerObjectIBase] = []
        # 开始处理-队列处理法
        while len(data_list) > 0:
            sub = data_list.pop(0) # pop(0)保证实例化的Der对象顺序正确
            sub_object: DerObjectIBase = ASN1DerObjectFactory.create_der_object(sub)
            if sub_object.tag == ASN1DerObjectTagsEnum.Sequence.value:
                data_list += self._split_sequence(sub_object.get_hex_raw())
            else:
                result_list.append(sub)
        return [ASN1DerObjectFactory.create_der_object(i) for i in result_list]

    def _split_sequence(self, value: str) -> List[str]:
        """ 拆分ASN1.Der.Sequence序列类型 """
        result_list: List[str] = []
        index: int = 0
        # 开始处理-index索引移动法
        while True:
            sub_length_len, sub_value_len = self._calculation_length(value[index:])
            sub_len: int = sub_length_len*2 + sub_value_len*2 + 2 # 整个子序列类型占的位数（字节数*2）
            result_list.append(value[index:index + sub_len])
            index += sub_len
            if index >= len(value): break
        return result_list
    
    def _calculation_length(self, value: str) -> Tuple[int, int]:
        """ 计算长度-返回字节数 """
        length_len: int # 计算结果
        first: str = value[2:4] # Length字段的第一个字节
        flag: bool = True if StringConvert.hex_convert_bin(first)[0] == "0" else False # 判断第一个字段的位7是否为0
        # 开始计算
        num_len: int = 0 if flag else StringConvert.bin_convert_int("0" + StringConvert.hex_convert_bin(first)[1:]) # 计算得到Length字段占用字节长度
        value_len: int = StringConvert.hex_convert_int(first) if flag else StringConvert.hex_convert_int(value[4: 4 + num_len*2])
        length_len = 1 if flag else num_len + 1
        # 返回Value字段实际长度
        return length_len, value_len