# 导入自定义库
from ..Error import ASN1DerProcessCode, ASN1DerProcessError
from ..Object.RawToASN1DerObject import RawToDerIBase, RawToASN1DerObjectsEnum, Sequence
from ..TagsEnum import ASN1DerObjectTagsEnum

class RawToASN1DerObjectFactory:
    """ 创建ASN1.Der对象-工厂 """

    @staticmethod
    def create_der_object(value: str, tag: str) -> RawToDerIBase:
        """ 创建对应的对象类型 """
        try:
            object_name: str = ASN1DerObjectTagsEnum(tag).name
            return RawToASN1DerObjectsEnum[object_name].value(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常
    
    @staticmethod
    def create_sequence_object(der1: RawToDerIBase, der2: RawToDerIBase) -> Sequence:
        """ 创建Sequence序列类型Der对象 """
        try:
            value: str = der1.get_hex_der() + der2.get_hex_der()
            return RawToASN1DerObjectsEnum.Sequence.value(value)
        except (ValueError, AttributeError):
            raise ASN1DerProcessError(ASN1DerProcessCode.ValueTypeError) # 抛出类型异常