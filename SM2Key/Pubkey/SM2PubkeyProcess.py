# 导入自定义类
from utils.StringConvert import StringConvert
from .Error import PubkeyProcessCode, PubkeyProcessError
from .SM2Pubkey import SM2Pubkey
from .PubkeyDer import PubkeyDer, PubkeyDerFactory

class SM2PubkeyProcess:
    """ 转换公钥主流程 """
    # 载入用户输入的公钥编码类型信息
    sm2_pubkey: SM2Pubkey = SM2Pubkey() # SM2公钥类
    pubkey_der: PubkeyDer # SM2公钥Der对象实例化
    _pubkey_type: str # 输入值的公钥类型

    def __init__(self, value: str) -> None:
        self.main(value)
        
    def main(self, value: str) -> None:
        """ 启动主流程 """
        # 获得输入的公钥值
        input_string: str = self._process_input_string(value)
        # 开始转换
        self.pubkey_der = PubkeyDerFactory.create_Raw2Der_PubkeyDer(input_string)  if self._pubkey_type == "Raw" else PubkeyDerFactory.create_Der2Raw_PubkeyDer(input_string)
        self.sm2_pubkey.hex_raw = self.pubkey_der.get_hex_raw_128()
        self.sm2_pubkey.base64_der = self.pubkey_der.get_base64_der()

    def _process_input_string(self, input_string: str) -> str:
        """ 处理输入内容为可处理格式-自动检测格式 """
        # 1、检查编码类型
        if not StringConvert.is_base64(input_string) and not StringConvert.is_hex(input_string):
            raise PubkeyProcessError(PubkeyProcessCode.StringTypeError) # 抛出编码类型报错
        # Base64编码统一处理为十六进制
        input_string = StringConvert.base64_convert_hex(input_string) if StringConvert.is_base64(input_string) else input_string
        # 2、检查格式类型
        if len(input_string) == 130 or len(input_string) == 128:
            # 若为Hex编码130长度带公钥标识，处理为128长度Hex编码Raw格式公钥
            input_string = input_string[-128:]
            self._pubkey_type = "Raw" # 确定公钥值类型为Raw格式
        elif len(input_string) > 130 and PubkeyDerFactory.is_hex_der_pubkey(input_string):
            self._pubkey_type = "Der" # 确定公钥值类型为Der格式
        else:
            raise PubkeyProcessError(PubkeyProcessCode.PubkeyTypeError) # 抛出公钥类型报错
        return input_string