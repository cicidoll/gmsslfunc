from math import ceil
from pysmx.SM3 import digest
from pysmx.SM2._SM2 import get_hash
import random
# 导入自定义库
from Calculate.EllipticCurve import SM2EllipticCurve
from Calculate.PointCalculate import kG

LEN_PARA = 64

class SM2Asymmetric:
    """ SM2非对称加解密 """

    # 素数域256位椭圆曲线参数
    elliptic_curve = SM2EllipticCurve

    def encrypt(self, plain_text: str, public_key: str) -> str:
        """
            SM2非对称加密算法
            :params plain_text utf-8字符集 Hex编码原文
            :params public_key 128长度Hex编码公钥
            :returns: String类型 Hex编码 C1C3C2 (C1: 04+x+y)
        """
        t: str = "0"
        while int(t, base=16)==0:
            k: int = random.randint(1, SM2EllipticCurve.n-1) # A1: 用随机数发生器产生整数d∈[1,n-1]
            C1: str = kG(k, "%64x%64x" % (self.elliptic_curve.G[0], self.elliptic_curve.G[1]), LEN_PARA) # A2: 多倍点计算C1=[k]G
            # A3: S=[h]PB 实际中余因子等于1，不需要这一步
            A4: str = kG(k, public_key, LEN_PARA) # A4: 多倍点计算 A4=[k]PB
            t: str = self._BKDF(A4, len(plain_text)/2).hex() # A5: t=KDF(x2||y2, klen) 设发送的消息为比特串M, klen为M的比特长度
        form = "%%0%dx" % len(plain_text)
        C2 =  form % (int(plain_text, base=16) ^ int(t, base=16))
        C3 = get_hash('sm3', A4[:LEN_PARA] + plain_text + A4[LEN_PARA:], Hexstr=1)
        return "04" + C1 + C3 + C2

    def decrypt(self, private_key: str, encrypted_data: str) -> str:
        """
            SM2非对称解密算法
            :params private_key 64长度Hex编码SM2私钥
            :params encrypted_data utf-8字符集 Hex编码 C1C3C2排列 (C1: 04+x+y)
            :returns: String类型-原文 Hex编码
        """
        encrypted_data = encrypted_data[2:] if encrypted_data[:2] == "04" else encrypted_data
        C1: str = encrypted_data[:2*LEN_PARA]
        C3: str = encrypted_data[2*LEN_PARA: 3*LEN_PARA]
        C2: str = encrypted_data[3*LEN_PARA:]

        B3: str = kG(int(private_key, base=16), C1, LEN_PARA) # B3: 多倍点计算 B3=[dB]C1
        B4: str = self._BKDF(B3, len(C2)/2).hex() # B4: t=KDF(x2||y2, klen) klen为密文中C2的比特长度
        if int(B4, base=16) == 0: return None
        form = "%%0%dx" % len(C2)
        B5: str = form % (int(C2, base=16) ^ int(B4, base=16))
        B6 = get_hash('sm3', B3[:LEN_PARA] + B5 + B3[LEN_PARA:], Hexstr=1)
        if B6 != C3: return None
        return B5
    
    @staticmethod
    def _BKDF(Z: str, klen: int) -> bytes:
        klen = int(klen)
        rcnt = int(ceil(klen / 32))
        Zin = SM2Asymmetric.__hex2byte(Z)
        b = bytearray()
        [b.extend(digest(Zin + SM2Asymmetric.__PUT_UINT32_BE(ct), 0)) for ct in range(1, rcnt + 1)]
        return b[:klen]

    @staticmethod
    def __hex2byte(msg: str):
        """
            16进制字符串转换成byte列表
            :param msg:
            :return:
        """
        if not isinstance(msg, str):
            raise ValueError("message must be string")
        ml = len(msg)
        if (ml & 1) != 0:
            msg = "0" + msg
        return list(bytes.fromhex(msg))
    
    @staticmethod
    def __PUT_UINT32_BE(n):
        return [int((n >> 24) & 0xff), int((n >> 16) & 0xff), int((n >> 8) & 0xff), int(n & 0xff)]