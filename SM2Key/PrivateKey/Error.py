from enum import Enum

""" 私钥类型处理异常定义 Start """

class PrivateKeyProcessCode(Enum):
    """ 错误码枚举类型 """
    Success: int = 0 # 成功
    StringTypeError: int = 20001 # 字符串编码类型报错
    PrivateKeyTypeError: int = 30001 # 私钥类型报错
    ErrorCode: int = 10001 # 通用报错

class PrivateKeyErrorTypeMatch:

    @classmethod
    def private_key_process_msg_match(cls, type: Enum) -> str:
        # -1标识无输入, 0为Base64编码, 1为Hex编码
        match type:
            case PrivateKeyProcessCode.Success:
                return "处理成功: Process Success"
            case PrivateKeyProcessCode.StringTypeError:
                return "输入私钥编码类型错误: String Type Error"
            case PrivateKeyProcessCode.PrivateKeyTypeError:
                return "输入私钥格式错误: PrivateKey Type Error"
            case _:
                return "处理异常: Process Failed"

class PrivateKeyProcessError(Exception):

    def __init__(self, error_type: Enum) -> None:
        super().__init__(self)
        self.error_info = PrivateKeyErrorTypeMatch.private_key_process_msg_match(error_type)

    def __str__(self) -> str:
        return self.error_info
    
""" 私钥类型处理异常定义 End """