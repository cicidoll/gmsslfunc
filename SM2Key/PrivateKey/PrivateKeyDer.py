from collections import Counter
from typing import List
# 导入自定义库
from ASN1Der import DerObjectIBase, ASN1DerObjectTagsEnum
from ASN1Der.Object import ASN1DerToRawObject, RawToASN1DerObject
from ASN1Der.Factory import RawToASN1DerObjectFactory, DerObjectsSplit
from SM2Key.SM2KeyCreate import calculate_public_key


""" SM2公钥信息-Der对象-GMT0010-2012 Start """
INTEGER_DATA_1 = "01"
OID_DATA_1 = "2A811CCF5501822D"
# 实例化Der子对象
INTEGER_1: RawToASN1DerObject.INTEGER = RawToASN1DerObject.INTEGER(INTEGER_DATA_1)
OID_1: RawToASN1DerObject.Oid = RawToASN1DerObject.Oid(OID_DATA_1)
A0_1: DerObjectIBase = RawToASN1DerObjectFactory.create_der_object(
    value = OID_1.get_hex_der(), tag = ASN1DerObjectTagsEnum.ContextSpecific_A0.value
    )

class PrivateKeyDerGMT00102012:
    """ SM2私钥信息-Der对象-GMT0010-2012 """

    def __init__(self) -> None:
        # 定义实例属性
        ## 私有属性-按序
        self._integer_1: DerObjectIBase = INTEGER_1 # INTEGER类型
        self._octet_string_1: DerObjectIBase = None # OCTETSTRING类型-记录Raw格式私钥
        self._oid_1: DerObjectIBase = OID_1 # OID类型
        self._a0_der: DerObjectIBase = A0_1
        self._bit_string_1: DerObjectIBase = None # 记录04标识Hex编码Raw格式长度130公钥
        self._a1_der: DerObjectIBase = None
        ## 公开属性
        self.private_key_der: DerObjectIBase = None # Sequence类型

    def _update_self_private_key(self) -> None:
        """ 更新self.private_key """
        self._a1_der = RawToASN1DerObjectFactory.create_der_object(self._bit_string_1.get_hex_der(), ASN1DerObjectTagsEnum.ContextSpecific_A1.value)
        self.private_key_der = RawToASN1DerObjectFactory.create_sequence_object(
            self._integer_1, self._octet_string_1,
            self._a0_der, self._a1_der
            )

    def get_hex_raw(self) -> str:
        """ 返回64长度的Hex编码Raw格式私钥 """
        return self._octet_string_1.get_hex_raw()
    
    def get_hex_der(self) -> str:
        """ 返回Hex编码的Der格式私钥 """
        return self.private_key_der.get_hex_der()
    
    def get_base64_der(self) -> str:
        """ 返回Base64编码的Der格式私钥 """
        return self.private_key_der.get_base64_der()


""" SM2私钥信息-Der对象-GMT0010-2012 End """

""" SM2私钥信息-Der对象-Factory-GMT0010-2012 Start """

class PrivateKeyDerGMT00102012Factory:
    """ SM2私钥信息-Der对象-Factory """

    @staticmethod
    def create_Raw2Der_PrivateKeyDer(private_key: str) -> PrivateKeyDerGMT00102012:
        """ Raw格式私钥-实例化Der对象
            :param private_key 十六进制的64长度SM2私钥
            :return PrivateKeyDerGMT00102012
        """
        # 实例化子Der对象
        public_key = "04" + calculate_public_key(private_key)
        octet_string_1: RawToASN1DerObject.OCTETSTRING = RawToASN1DerObjectFactory.create_der_object(value=private_key, tag=ASN1DerObjectTagsEnum.OCTETSTRING.value)
        bit_string_1: RawToASN1DerObject.BitString = RawToASN1DerObjectFactory.create_der_object(value=public_key, tag=ASN1DerObjectTagsEnum.BitString.value)
        # 将子Der对象更新至PrivateKeyDer
        private_key_der_object: PrivateKeyDerGMT00102012 = PrivateKeyDerGMT00102012()
        private_key_der_object._octet_string_1 = octet_string_1
        private_key_der_object._bit_string_1 = bit_string_1
        private_key_der_object._update_self_private_key()
        return private_key_der_object   

    @staticmethod
    def create_Der2Raw_PrivateKeyDer(input_hex_der: str) -> PrivateKeyDerGMT00102012:
        """ Der格式私钥-实例化Der对象
            :param input_hex_der 十六进制的Der格式SM2私钥
            :return PrivateKeyDerGMT00102012
        """
        der_objects_list: List[DerObjectIBase] = DerObjectsSplit(input_hex_der).der_objects_list
        # 将子Der对象更新至PrivateKeyDer
        private_key_der_object: PrivateKeyDerGMT00102012 = PrivateKeyDerGMT00102012()
        private_key_der_object._octet_string_1 = [i for i in der_objects_list if i.__class__ == ASN1DerToRawObject.OCTETSTRING].pop(0)
        private_key_der_object._bit_string_1 = [i for i in der_objects_list if i.__class__ == ASN1DerToRawObject.BitString].pop(0)
        private_key_der_object._update_self_private_key()
        return private_key_der_object   

    @staticmethod
    def is_hex_der_private_key(input_hex_der: str) -> bool:
        """ 检测是否为Der格式私钥 """
        assert_result: list = [ASN1DerToRawObject.INTEGER, ASN1DerToRawObject.OCTETSTRING, ASN1DerToRawObject.BitString]
        der_objects_list: List[DerObjectIBase] = DerObjectsSplit(input_hex_der).der_objects_list
        diff_add_list: list = [ i.__class__ for i in der_objects_list if i.__class__ in assert_result]
        # Der格式公钥会解析出：INTEGER*1  OCTETSTRING*1 BitString*1
        return True if Counter(diff_add_list) == Counter(assert_result) else False

""" SM2私钥信息-Der对象-Factory-GMT0010-2012 End """