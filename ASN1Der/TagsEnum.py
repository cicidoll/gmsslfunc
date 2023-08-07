from enum import Enum

class ASN1DerObjectTagsEnum(Enum):
    """ ASN1Der对象类型-Tag枚举 """
    Sequence: str = "30" # Sequence-序列类型
    Oid: str = "06" # OID-对象标识符类型
    BitString: str = "03" # BIT STRING类型
    INTEGER: str = "02" # INTEGER类型
    OCTETSTRING: str = "04" # OCTET STRING类型-八进制字符串
    ContextSpecific_A0: str = "A0" # 私钥Der对象-标签A0
    ContextSpecific_A1: str = "A1" # 私钥Der对象-标签A1