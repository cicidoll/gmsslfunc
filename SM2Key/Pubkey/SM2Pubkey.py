class SM2Pubkey:
    """ SM2公钥类 """

    def __init__(self) -> None:
        self.hex_raw: str # Raw格式Hex编码公钥值-128长度
        self.base64_der: str # Der格式Base64编码公钥值