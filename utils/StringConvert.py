import base64, re

class StringConvert:
    """ 字符串格式转换方法 """

    @staticmethod
    def base64_convert_hex(input_base64: str) -> str:
        """ 将base64转换为hex字符串-输出小写 """
        return str(base64.b64decode(input_base64).hex())
    
    @staticmethod
    def hex_convert_base64(input_hex: str) -> str:
        """ 将hex转换为base64字符串 """
        return str(base64.b64encode(bytes.fromhex(input_hex)))[2:-1]
    
    @staticmethod
    def is_base64(input_str: str) -> bool:
        """ 检测字符串是否为Base64编码 """
        base64_code = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
        return not StringConvert.is_hex(input_str) and bool(re.match(base64_code, input_str))
    
    @staticmethod
    def is_hex(input_str: str) -> bool:
        """ 检测字符串是否为Hex编码 """
        hex_code = "\A[0-9a-fA-F]+\Z"
        return bool(re.match(hex_code, input_str))
    
    @staticmethod
    def hex_convert_int(input: str) -> int:
        """ 十六进制转十进制 """
        return int(input, 0) if "0x" in input else int(input, 16)
    
    @staticmethod
    def int_convert_hex(input: int) -> str:
        """ 十进制转十六进制 """
        input = hex(input).replace("0x", "")
        value: str = input if len(input) % 2 == 0 else "0" + input
        return value

    @staticmethod
    def hex_convert_bin(input: str) -> str:
        """ 将十六进制转换为二进制 """
        input = input.replace("0x", "") # 去除前缀
        value: str = bin(int(input, 16)).replace("0b", "")
        value = value if len(value) % 8 == 0 else "0"*(8 - len(value)%8) + value
        return value
    
    @staticmethod
    def bin_convert_hex(input: str) -> str:
        """ 将二进制转换为十六进制 """
        input = input.replace("0b", "") # 去除前缀
        value: str = hex(int(input, 2)).replace("0x", "")
        value = value if len(value) % 2 == 0 else "0" + value
        return value
    
    @staticmethod
    def bin_convert_int(input: str) -> int:
        """ 将二进制转换为十进制 """
        input = input.replace("0b", "") # 去除前缀
        return int(input, 2)