from Calculate.EllipticCurve import SM2EllipticCurve
from SM2Key import calculate_public_key
import random

class SM2KeyCreate:
    """ SM2公私钥对-Object """
    # 私钥 hex格式
    private_key: str
    # 公钥(开头04) hex格式
    public_key: str

    def __init__(self) -> None:
        """ 初始化 """
        # 生成随机十进制私钥
        private_key = self.__create_private_key()
        # 公私钥赋值
        self.public_key = "04" + calculate_public_key(private_key)
        self.private_key = hex(private_key).replace('0x', '').zfill(64)

    def __create_private_key(self) -> int:
        """ 产生随机私钥
            [GM/T 0003]规范定义 用随机数发生器产生整数d∈[1,n-2]
        """
        return random.randint(1, SM2EllipticCurve.n - 2)