from pysmx.SM3 import hash_msg
import random, math, binascii
# 导入自定义库
from Calculate.EllipticCurve import SM2EllipticCurve
from Calculate.PointCalculate import kG
from utils.StringConvert import StringConvert

LEN_PARA = 64

class SM2Asymmetric:
    """ SM2非对称加解密 """

    # 素数域256位椭圆曲线参数
    elliptic_curve = SM2EllipticCurve

    def encrypt(self, plain_text: str, public_key: str = "") -> str:
        """
            SM2非对称加密算法
            :params plain_text utf-8字符集 Base64编码原文
            :params public_key 128长度Hex编码公钥
            :returns: String类型 Hex编码 C1C3C2
        """
        t: str = "0"
        while int(t, base=16)==0:
            k: int = random.randint(1, SM2EllipticCurve.n-1) # A1: 用随机数发生器产生整数d∈[1,n-1]
            C1: str = kG(k, "%64x%64x" % (self.elliptic_curve.G[0], self.elliptic_curve.G[1]), LEN_PARA) # A2: 多倍点计算C1=[k]G
            # A3: S=[h]PB 实际中余因子等于1，不需要这一步
            A4: str = kG(k, public_key, LEN_PARA) # A4: 多倍点计算 A4=[k]PB
            t: str = self._sm3_kdf(A4.encode("utf-8"), len(StringConvert.base64_convert_hex(plain_text))/2) # A5: t=KDF(x2||y2, klen) 设发送的消息为比特串M, klen为M的比特长度
        form = "%%0%dx" % len(StringConvert.base64_convert_hex(plain_text))
        C2 =  form % (int(StringConvert.base64_convert_hex(plain_text), base=16) ^ int(t, base=16))
        C3 = hash_msg(A4[:64]+StringConvert.base64_convert_hex(plain_text)+A4[64:])
        return C1 + C3 + C2

    def decrypt(self, private_key: str, encrypted_data: str) -> str:
        """
            SM2非对称解密算法
            :params private_key 64长度Hex编码SM2私钥
            :params encrypted_data utf-8字符集 Hex编码 C1C3C2排列
            :returns: String类型-原文 Hex编码
        """
        C1: str = encrypted_data[:2*LEN_PARA]
        C3: str = encrypted_data[2*LEN_PARA: 3*LEN_PARA]
        C2: str = encrypted_data[3*LEN_PARA:]

        B3: str = kG(int(private_key, base=16), C1, LEN_PARA) # B3: 多倍点计算 B3=[dB]C1
        B4: str = self._sm3_kdf(B3.encode("utf-8"), len(C2)/2) # B4: t=KDF(x2||y2, klen) klen为密文中C2的比特长度
        if int(B4, base=16) == 0: return None
        form = "%%0%dx" % len(C2)
        B5: str = form % (int(C2, base=16) ^ int(B4, base=16))
        B6 = hash_msg(B3[:64] + B5 + B3[64:])
        if B6 != C3: return None
        return B5

    @staticmethod
    def _sm3_kdf(z: bytes, klen: int):
        """
            密钥派生函数
            :params z bytes 16进制比特串(str)
            :params klen 密钥长度(单位 byte)
        """
        klen: int = int(klen)
        ct = 0x00000001
        rcnt = math.ceil(klen/32)
        zin = [i for i in bytes.fromhex(z.decode('utf-8'))]
        ha = ""
        for _ in range(rcnt):
            msg = zin + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf-8'))]
            ha += hash_msg(msg)
            ct += 1
        return ha[0: klen * 2]