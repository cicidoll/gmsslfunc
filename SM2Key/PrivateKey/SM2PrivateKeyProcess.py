# 导入自定义类
from utils.StringConvert import StringConvert
from .Error import PrivateKeyProcessCode, PrivateKeyProcessError
from .SM2PrivateKey import SM2PrivateKey
from .PrivateKeyDer import PrivateKeyDerGMT00102012, PrivateKeyDerGMT00102012Factory

PRIVATE_KEY_LEN_RAW = 64

class SM2PrivateKeyProcess:
    """ 转换SM2私钥主流程 """
    # 载入用户输入的私钥编码类型信息
    sm2_private_key: SM2PrivateKey = SM2PrivateKey() # SM2私钥类
    private_key_der: PrivateKeyDerGMT00102012 # SM2私钥Der对象实例化
    _private_key_type: str # 输入值的私钥类型

    def __init__(self, value: str) -> None:
        self.main(value)
        
    def main(self, value: str) -> None:
        """ 启动主流程 """
        # 获得输入的私钥值
        input_string: str = self._process_input_string(value)
        # 开始转换
        self.private_key_der = PrivateKeyDerGMT00102012Factory.create_Raw2Der_PrivateKeyDer(input_string)  if self._private_key_type == "Raw" else PrivateKeyDerGMT00102012Factory.create_Der2Raw_PrivateKeyDer(input_string)
        self.sm2_private_key.hex_raw = self.private_key_der.get_hex_raw()
        self.sm2_private_key.base64_der = self.private_key_der.get_base64_der()

    def _process_input_string(self, input_string: str) -> str:
        """ 处理输入内容为可处理格式-自动检测格式 """
        # 1、检查编码类型
        if not StringConvert.is_base64(input_string) and not StringConvert.is_hex(input_string):
            raise PrivateKeyProcessError(PrivateKeyProcessCode.StringTypeError) # 抛出编码类型报错
        # Base64编码统一处理为十六进制
        input_string = StringConvert.base64_convert_hex(input_string) if StringConvert.is_base64(input_string) else input_string
        # 2、检查格式类型
        if len(input_string) == PRIVATE_KEY_LEN_RAW:
            self._private_key_type = "Raw" # 确定私钥值类型为Raw格式
        elif len(input_string) > PRIVATE_KEY_LEN_RAW and PrivateKeyDerGMT00102012Factory.is_hex_der_private_key(input_string):
            self._private_key_type = "Der" # 确定私钥值类型为Der格式
        else:
            raise PrivateKeyProcessError(PrivateKeyProcessCode.PrivateKeyTypeError) # 抛出私钥类型报错
        return input_string