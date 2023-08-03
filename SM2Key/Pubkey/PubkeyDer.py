from collections import Counter
from typing import List
# 导入自定义库
from ASN1Der import DerObjectIBase, ASN1DerObjectTagsEnum
from ASN1Der.Object.RawToASN1DerObject import Oid, Sequence
from ASN1Der.Object import ASN1DerToRawObject
from ASN1Der.Factory import RawToASN1DerObjectFactory, DerObjectsSplit

# 固定值
# 301306072A8648CE3D020106082A811CCF5501822D
OID_DATA_1 = "2A8648CE3D0201"
OID_DATA_2 = "2A811CCF5501822D"
# OID Der对象实例化
OID_1: Oid = Oid(OID_DATA_1)
OID_2: Oid = Oid(OID_DATA_2)
SUB_SEQUENCE_1: Sequence = RawToASN1DerObjectFactory.create_sequence_object(OID_1, OID_2)

class PubkeyDer:
    """ SM2公钥信息-Der对象 """

    def __init__(self) -> None:
        # 定义实例属性
        ## 私有属性
        self._oid_1: DerObjectIBase = OID_1 # OID类型
        self._oid_2: DerObjectIBase = OID_2 # OID类型
        self._sub_sequence_1: DerObjectIBase = SUB_SEQUENCE_1 # Sequence类型
        self._bit_string: DerObjectIBase # BIT STRING类型
        ## 公开属性
        self.pubkey_der: DerObjectIBase # Sequence类型

    def _update_self_pubkey_der(self) -> None:
        """ 更新self.pubkey_der """
        self.pubkey_der = RawToASN1DerObjectFactory.create_sequence_object(self._sub_sequence_1, self._bit_string)

    def get_hex_raw_128(self) -> str:
        """ 返回128长度的Hex编码Raw格式公钥 """
        return self._bit_string.get_hex_raw()[-128:]
    
    def get_hex_raw_130(self) -> str:
        """ 返回130长度带04标识的Hex编码Raw格式非压缩公钥 """
        return "04" + self.get_hex_raw_128()
    
    def get_hex_der(self) -> str:
        """ 返回Hex编码的Der格式公钥 """
        return self.pubkey_der.get_hex_der()
    
    def get_base64_der(self) -> str:
        """ 返回Base64编码的Der格式公钥 """
        return self.pubkey_der.get_base64_der()

class PubkeyDerFactory:
    """ 公钥Der对象工厂 """

    @staticmethod
    def create_Raw2Der_PubkeyDer(input_str: str) -> PubkeyDer:
        """ Raw格式公钥-实例化Der对象
            :param input_str 十六进制的128长度SM2公钥
            :return PubkeyDer
        """
        input_str = "04" + input_str
        pubkey_der_object = PubkeyDer()
        pubkey_der_object._bit_string = RawToASN1DerObjectFactory.create_der_object(input_str, ASN1DerObjectTagsEnum.BitString.value)
        pubkey_der_object._update_self_pubkey_der()
        return pubkey_der_object   

    @staticmethod
    def create_Der2Raw_PubkeyDer(input_str: str) -> PubkeyDer:
        """ Der格式公钥-实例化Der对象
            :param input_str 十六进制的Der格式SM2公钥
            :return PubkeyDer
        """
        pubkey_der_object = PubkeyDer()
        pubkey_der_object._bit_string = [i for i in DerObjectsSplit(input_str).der_objects_list if i.__class__ == ASN1DerToRawObject.BitString].pop(0)
        pubkey_der_object._update_self_pubkey_der()
        return pubkey_der_object

    @staticmethod
    def is_hex_der_pubkey(input_string: str) -> bool:
        """ 检测是否为der格式公钥 """
        assert_result: list = [ASN1DerToRawObject.Oid, ASN1DerToRawObject.Oid, ASN1DerToRawObject.BitString]
        der_objects_list: List[ASN1DerToRawObject.DerToRawIBase] = DerObjectsSplit(input_string).der_objects_list
        diff_add_list: list = [ i.__class__ for i in der_objects_list if i.__class__ in assert_result]
        # Der格式公钥会解析出来两个Oid和一个BIT STRING
        return True if Counter(diff_add_list) == Counter(assert_result) else False