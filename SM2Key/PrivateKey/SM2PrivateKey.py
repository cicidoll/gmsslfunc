class SM2PrivateKey:
    """ SM2私钥类 """

    def __init__(self) -> None:
        self.hex_raw: str # Raw格式Hex编码私钥值-64长度
        self.base64_der: str # Der格式Base64编码私钥值