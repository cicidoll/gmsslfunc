from typing import List, Tuple, Union
# 导入自定义库
from ASN1Der import ASN1DerObjectTagsEnum
from SM2Key.PrivateKey import SM2PrivateKeyProcess
from SM2Key.Pubkey import SM2PubkeyProcess
from ASN1Der.Factory import RawToASN1DerObjectFactory, DerObjectsSplit
from ASN1Der.Object.RawToASN1DerObject import Sequence as RawToASN1DerSequence
from ASN1Der.Object.ASN1DerToRawObject import INTEGER as ASN1DerToRawINTEGER
from ASN1Der.Object.ASN1DerToRawObject import OCTETSTRING as ASN1DerToRawOCTETSTRING
from ASN1Der.Object import DerObjectIBase
from utils.StringConvert import StringConvert
from .SM2 import SM2Asymmetric

class SM2AsymmetricDer:
    """ SM2非对称加解密-支持Der格式 """
    # 组合-SM2非对称加解密类
    sm2_asymmetric: SM2Asymmetric = SM2Asymmetric()

    def encrypt(self, plain_text: str, public_key: str, asn1_der: bool = False) -> str:
        """
            SM2非对称加密算法
            :params plain_text utf-8字符集 Base64编码原文
            :params public_key 支持: 128长度Raw格式Hex编码公钥/130长度Raw格式Hex编码公钥/Der格式Base64编码公钥/Der格式Hex编码公钥
            :params asn1_der True: 输出Der格式Base64编码加密值; False: 输出Raw格式Hex编码加密值
            :returns: String类型 C1C3C2 (C1: 04+x+y)
        """
        plain_text: str = StringConvert.base64_convert_hex(plain_text) # Base64编码转Hex编码
        public_key: str = SM2PubkeyProcess(public_key).pubkey_der.get_hex_raw_128() # 处理SM2公钥
        encrypted_data: str = self.sm2_asymmetric.encrypt(
            plain_text = plain_text,
            public_key = public_key
        )
        if asn1_der == False: return encrypted_data # 输出Raw格式Hex编码加密值
        # Raw格式密文值转Der格式处理
        encrypted_data = encrypted_data[2:] if encrypted_data[:2] == "04" else encrypted_data # 去掉04标识位
        C1 = encrypted_data[:128]
        C1X, C1Y = C1[:64], C1[64:]
        C3 = encrypted_data[128:192]
        C2 = encrypted_data[192:]
        encrypted_data: RawToASN1DerSequence = RawToASN1DerObjectFactory.create_sequence_object(
            # 将C1 C3 C2转换为Der对象
            RawToASN1DerObjectFactory.create_der_object(C1X, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C1Y, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C3, ASN1DerObjectTagsEnum.OCTETSTRING.value),
            RawToASN1DerObjectFactory.create_der_object(C2, ASN1DerObjectTagsEnum.OCTETSTRING.value),
        ).get_base64_der()
        return encrypted_data
    
    def decrypt(self, private_key: str, encrypted_data: str, asn1_der = bool) -> str:
        """
            SM2非对称解密算法
            :params private_key 支持: 64长度Raw格式Hex编码SM2私钥 || Der格式Base64编码SM2私钥
            :params encrypted_data utf-8字符集 C1C3C2排列 (C1: 04+x+y)
            :params asn1_der True: 输入Der格式Base64编码加密值; False: 输入Raw格式Hex编码加密值
            :returns: String类型-原文 Base64编码
        """
        private_key: str = SM2PrivateKeyProcess(private_key).private_key_der.get_hex_raw() # 处理SM2私钥
        # 处理encrypted_data
        if asn1_der == True:
            encrypted_data_der_list: List[DerObjectIBase] = DerObjectsSplit(StringConvert.base64_convert_hex(encrypted_data)).der_objects_list
            C1 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawINTEGER)])
            C3 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING) and len(i.get_hex_raw()) == 64])
            C2 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING) and i.get_hex_raw() != C3])
            encrypted_data: str = "04" + C1 + C3 +C2
        # 解密
        plain_text_data: str = self.sm2_asymmetric.decrypt(
            private_key = private_key, 
            encrypted_data = encrypted_data
        )
        return StringConvert.hex_convert_base64(plain_text_data)
    
class SM2AsymmetricEncryptedDataConvert:
    """ SM2非对称加解密-密文格式转换 """

    ### C1C2C3Der格式与C1C3C2Der格式互相转换

    @staticmethod
    def C1C2C3Der_to_C1C3C2Der(encrypted_data: str) -> str:
        """
        C1C2C3_Der格式转换为C1C3C2_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C2C3Der_split_C1C2C3(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C3C2Der(C1, C2, C3)

    @staticmethod
    def C1C3C2Der_to_C1C2C3Der(encrypted_data: str) -> str:
        """
        C1C3C2_Der格式转换为C1C2C3_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C3C2Der_split_C1C2C3(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C2C3Der(C1, C2, C3)

    ### (C1C2C3、C1C3C2)Der格式转换为(C1C2C3、C1C3C2)Raw格式

    @staticmethod
    def C1C2C3Der_to_C1C2C3Raw(encrypted_data: str) -> str:
        """
        C1C2C3_Der格式转换为C1C2C3_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C2C3Der_split_C1C2C3(encrypted_data)
        return "04" + C1 + C2 + C3
    
    @staticmethod
    def C1C3C2Der_to_C1C2C3Raw(encrypted_data: str) -> str:
        """
        C1C3C2_Der格式转换为C1C2C3_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C3C2Der_split_C1C2C3(encrypted_data)
        return "04" + C1 + C2 + C3

    @staticmethod
    def C1C2C3Der_to_C1C3C2Raw(encrypted_data: str) -> str:
        """
        C1C2C3_Der格式转换为C1C3C2_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C2C3Der_split_C1C2C3(encrypted_data)
        return "04" + C1 + C3 + C2

    @staticmethod
    def C1C3C2Der_to_C1C3C2Raw(encrypted_data: str) -> str:
        """
        C1C3C2_Der格式转换为C1C2C3_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._C1C3C2Der_split_C1C2C3(encrypted_data)
        return "04" + C1 + C3 + C2

    ### C1C2C3_Raw格式与C1C3C2_Raw格式互相转换

    @staticmethod
    def C1C2C3Raw_to_C1C3C2Raw(encrypted_data: str) -> str:
        """
        C1C2C3_Raw格式转换为C1C3C2_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C2C3(encrypted_data)
        return "04" + C1 + C3 + C2
    
    @staticmethod
    def C1C3C2Raw_to_C1C2C3Raw(encrypted_data: str) -> str:
        """
        C1C3C2_Raw格式转换为C1C2C3_Raw格式
        :params encrypted_data String类型 加密值
        :return String类型 输出整串加密值
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C3C2(encrypted_data)
        return "04" + C1 + C2 + C3
    
    ### (C1C2C3、C1C3C2)Raw格式转换为(C1C2C3、C1C3C2)Der格式

    @staticmethod
    def C1C3C2Raw_to_C1C3C2Der(encrypted_data: str) -> str:
        """
        C1C3C2_Raw格式转换为C1C3C2_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出C1C3C2加密值的Der格式
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C3C2(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C3C2Der(C1, C2, C3)
    
    @staticmethod
    def C1C2C3Raw_to_C1C3C2Der(encrypted_data: str) -> str:
        """
        C1C2C3_Raw格式转换为C1C3C2_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出C1C3C2加密值的Der格式
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C2C3(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C3C2Der(C1, C2, C3)

    @staticmethod
    def C1C3C2Raw_to_C1C2C3Der(encrypted_data: str) -> str:
        """
        C1C3C2_Raw格式转换为C1C2C3_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出C1C2C3加密值的Der格式
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C3C2(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C2C3Der(C1, C2, C3)
    
    @staticmethod
    def C1C2C3Raw_to_C1C2C3Der(encrypted_data: str) -> str:
        """
        C1C2C3_Raw格式转换为C1C3C2_Der格式
        :params encrypted_data String类型 加密值
        :return String类型 输出C1C3C2加密值的Der格式
        """
        C1, C2, C3 = SM2AsymmetricEncryptedDataConvert._split_C1C2C3(encrypted_data)
        return SM2AsymmetricEncryptedDataConvert._C1C2C3_to_C1C2C3Der(C1, C2, C3)

    ### 私有函数-将(C1C2C3、C1C3C2)Der格式转换为C1、C2、C3

    @staticmethod
    def _C1C3C2Der_split_C1C2C3(encrypted_data: str) -> Tuple[str]:
        """
        C1C3C2_Der格式转换为C1、C2、C3
        :params encrypted_data String类型 加密值
        :return tuple类型 输出C1, C2, C3
        """
        encrypted_data_der_list: List[DerObjectIBase] = DerObjectsSplit(StringConvert.base64_convert_hex(encrypted_data)).der_objects_list
        C1 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawINTEGER)])
        C3 = [i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING)][0] #TODO 鉴别C2C3的方法只能是按照拆分出来的OctetString对象顺序 暂时没想到有什么二重鉴别的方法
        C2 = [i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING)][1]
        return C1, C2, C3

    @staticmethod
    def _C1C2C3Der_split_C1C2C3(encrypted_data: str) -> Tuple[str]:
        """
        C1C3C2_Der格式转换为C1、C2、C3
        :params encrypted_data String类型 加密值
        :return tuple类型 输出C1, C2, C3
        """
        encrypted_data_der_list: List[DerObjectIBase] = DerObjectsSplit(StringConvert.base64_convert_hex(encrypted_data)).der_objects_list
        C1 = "".join([i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawINTEGER)])
        C2 = [i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING)][0] #TODO 鉴别C2C3的方法只能是按照拆分出来的OctetString对象顺序 暂时没想到有什么二重鉴别的方法
        C3 = [i.get_hex_raw() for i in encrypted_data_der_list if isinstance(i, ASN1DerToRawOCTETSTRING)][1]
        return C1, C2, C3

    ### 私有函数-将C1、C2、C3转换为(C1C2C3、C1C3C2)Der格式

    @staticmethod
    def _C1C2C3_to_C1C3C2Der(C1: str, C2: str, C3: str) -> str:
        """
        将C1 C2 C3 转换为C1C3C2_Der格式
        :params C1 String类型
        :params C2 String类型
        :params C3 String类型
        :return String类型 输出C1C3C2加密值的Der格式
        """
        C1X, C1Y = C1[:64], C1[64:]
        encrypted_data: RawToASN1DerSequence = RawToASN1DerObjectFactory.create_sequence_object(
            # 将C1 C3 C2转换为Der对象
            RawToASN1DerObjectFactory.create_der_object(C1X, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C1Y, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C3, ASN1DerObjectTagsEnum.OCTETSTRING.value),
            RawToASN1DerObjectFactory.create_der_object(C2, ASN1DerObjectTagsEnum.OCTETSTRING.value),
        ).get_base64_der()
        return encrypted_data

    @staticmethod
    def _C1C2C3_to_C1C2C3Der(C1: str, C2: str, C3: str) -> str:
        """
        将C1 C2 C3 转换为C1C2C3_Der格式
        :params C1 String类型
        :params C2 String类型
        :params C3 String类型
        :return String类型 输出C1C2C3加密值的Der格式
        """
        C1X, C1Y = C1[:64], C1[64:]
        encrypted_data: RawToASN1DerSequence = RawToASN1DerObjectFactory.create_sequence_object(
            # 将C1 C2 C3转换为Der对象
            RawToASN1DerObjectFactory.create_der_object(C1X, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C1Y, ASN1DerObjectTagsEnum.INTEGER.value),
            RawToASN1DerObjectFactory.create_der_object(C2, ASN1DerObjectTagsEnum.OCTETSTRING.value),
            RawToASN1DerObjectFactory.create_der_object(C3, ASN1DerObjectTagsEnum.OCTETSTRING.value),
        ).get_base64_der()
        return encrypted_data

    ### 私有函数-切割加密值得到C1、C2、C3

    @staticmethod
    def _split_C1C2C3(encrypted_data: str) -> Tuple[str]:
        """
        将包含04标识符的C1C2C3加密值切分出C1 C2 C3
        :params encrypted_data String类型 加密值
        :return tuple类型 输出C1, C2, C3
        """
        encrypted_data = encrypted_data[2:] if encrypted_data[:2] == "04" else encrypted_data # 去掉04标识位
        C1 = encrypted_data[:128]
        C2 = encrypted_data[128:-64]
        C3 = encrypted_data[-64:]
        return C1, C2, C3

    @staticmethod
    def _split_C1C3C2(encrypted_data: str) -> Tuple[str]:
        """
        将包含04标识符的C1C3C2加密值切分出C1 C2 C3
        :params encrypted_data String类型 加密值
        :return tuple类型 输出C1, C2, C3
        """
        encrypted_data = encrypted_data[2:] if encrypted_data[:2] == "04" else encrypted_data # 去掉04标识位
        C1 = encrypted_data[:128]
        C3 = encrypted_data[128:192]
        C2 = encrypted_data[192:]
        return C1, C2, C3