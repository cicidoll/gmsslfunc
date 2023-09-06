from enum import Enum
from typing import Dict, Any

class ReturnsCode(Enum):
    """ RawAPI-返回值-Code枚举 """

    SUCCESS: Dict[str, int] = {"code": 0} # 调用成功
    HANDLE_ERROR: Dict[str, int] = {"code": 23222} # 函数调用失败
    INPUT_ERROR: Dict[str, int] = {"code": 23186} # 参数传入错误


class ReturnsMsg(Enum):
    """ RawAPI-返回值-Msg枚举 """

    SUCCESS: Dict[str, str] = {"msg": "成功"}
    HANDLE_ERROR: Dict[str, str] = {"msg": "函数调用失败"}
    INPUT_ERROR: Dict[str, str] = {"msg": "参数传入错误，请检查"}
    DECRYPT_ERROR: Dict[str, str] = {"msg": "解密失败"}


class ReturnsData(Enum):
    """ SM2_Asymmetric_API-返回值-Data枚举 """

    ENCRYPT: str = "encryptedData"
    DECRYPT: str = "plainText"


class Returns(Enum):
    """ RawAPI-返回值-枚举 """

    SUCCESS: Dict[str, Any] = {
        **ReturnsCode.SUCCESS.value,
        **ReturnsMsg.SUCCESS.value
    }
    HANDLE_ERROR: Dict[str, Any] = {
        **ReturnsCode.HANDLE_ERROR.value,
        **ReturnsMsg.HANDLE_ERROR.value
    }
    INPUT_ERROR: Dict[str, Any] = {
        **ReturnsCode.INPUT_ERROR.value,
        **ReturnsMsg.INPUT_ERROR.value
    }
    DECRYPT_ERROR: Dict[str, Any] = {
        **ReturnsCode.HANDLE_ERROR.value,
        **ReturnsMsg.DECRYPT_ERROR.value
    }