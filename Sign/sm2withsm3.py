from pysmx.SM3 import hash_msg
from interval import Interval
from typing import Tuple, List
import random
# 导入自定义库
from SM2Key.SM2KeyCreate import calculate_public_key
from Calculate.EllipticCurve import SM2EllipticCurve
from Calculate.PointCalculate import kG, PointCalculate
from Calculate.ModCalculate import int_mod, decimal_mod
from SM2Key.Pubkey import SM2PubkeyProcess

LEN_PARA = 64

def hex_zfill(input: str) -> str:
    return input.replace("0x", "") if len(input) % 2 == 0 else ("0" + input).replace("0x", "")

def bytes_sm3(input: str) -> str:
    """ 十六进制进行SM3摘要计算 """
    return hash_msg(bytes.fromhex(input))

class SM2withSM3Sign:
    # 素数域256位椭圆曲线参数
    elliptic_curve = SM2EllipticCurve

    def __init__(self, private_key: str, public_key: str = "") -> None:
        """ 初始化
            :params private_key Hex编码Raw格式私钥
            :params public_key Hex编码Raw格式128长度公钥
        """
        # 赋值实例属性
        self.public_key = public_key if public_key != "" else calculate_public_key(private_key)
        self.private_key = private_key

    def sign(self, msg: str, userid: str = "1234567812345678") -> str:
        """ SM2withSM3签名
            :params msg utf-8编码原文
            :params userid 使用默认1234567812345678
            :return 字符串类型 返回Raw格式Hex编码128长度的签名值
        """
        A2: int = int(self._A1andA2(msg, userid), base=16) # 十六进制
        R, S = self._A3A4A5A6(A2)
        return "%s%s" % (hex(R).replace("0x", "").zfill(64), hex(S).replace("0x", "").zfill(64))

    def _A1andA2(self, msg: str, userid: str) -> str:
        """ A1A2计算过程 """
        IDA: str = userid.encode('utf-8').hex() # userid 
        ENTLA: str = hex_zfill(hex(int(len(IDA) / 2)*8)).zfill(4) # hex格式
        a, b, Gx, Gy = map(hex_zfill, map(hex, (self.elliptic_curve.a, self.elliptic_curve.b, self.elliptic_curve._Gx, self.elliptic_curve._Gy)))
        ZA = bytes_sm3((ENTLA+IDA+a+b+Gx+Gy+self.public_key).lower())
        M1 = ZA + hex_zfill(msg.encode("utf-8").hex())
        A2 = bytes_sm3(M1)
        return A2

    def _A3A4A5A6(self, A2: int) -> Tuple[int, int]:
        """ A3A4A5A6计算过程 """
        while True:
            k: int = random.randint(1, self.elliptic_curve.n - 2) # A3
            x1 = int(kG(k, "%64x%64x" % (self.elliptic_curve.G[0], self.elliptic_curve.G[1]), LEN_PARA)[:64], 16) # A4
            R: int = int_mod((A2 + x1), self.elliptic_curve.n) # A5
            if R == 0 or R + k == 0: continue # 若R值为0或R+k为0，重新计算
            S: int = decimal_mod(k - R * int(self.private_key, 16), 1 + int(self.private_key, 16), self.elliptic_curve.n) # A6
            if S == 0: continue # 若S值为0，重新计算
            break
        return R, S

class SM2withSM3Verify:
    # 素数域256位椭圆曲线参数
    elliptic_curve = SM2EllipticCurve

    def verify(self, plain_text: str, signed_text: str, pubkey: str, userid: str = "1234567812345678") -> bool:
        """ 验证Raw格式SM2withSM3裸签名
            :params plain_text utf-8编码原文
            :params signed_text 签名值 当asn1_der为True时，输入Der格式Base64编码签名值；当asn1_der为False时，输入Raw格式Hex编码128长度的签名值
            :params pubkey Hex编码128长度公钥
            :params userid 使用默认1234567812345678 
            :params asn1_der 是否输入Der格式Base64编码签名
            :return 布尔类型 验签结果
        """
        R = signed_text[:64]
        S = signed_text[64:]
        if self._B1B2(R, S) == False: return False
        # SM2公钥兼容处理
        pubkey = SM2PubkeyProcess(pubkey).sm2_pubkey.hex_raw
        B4 = self._B3B4(plain_text, pubkey, userid)
        return self._B5B6B7(R, S, pubkey, B4)

    def _B1B2(self, R: str, S: str) -> bool:
        n = self.elliptic_curve.n
        zoom_1_n1 = Interval(1, n-1)
        return int(R, 16) in zoom_1_n1 and int(S, 16) in zoom_1_n1
    
    def _B3B4(self, plain_text: str, pubkey: str, userid: str) -> int:
        IDA: str = userid.encode('utf-8').hex() # userid 
        ENTLA: str = hex_zfill(hex(int(len(IDA) / 2)*8)).zfill(4) # hex格式
        a, b, Gx, Gy = map(hex_zfill, map(hex, (self.elliptic_curve.a, self.elliptic_curve.b, self.elliptic_curve._Gx, self.elliptic_curve._Gy)))
        ZA = bytes_sm3((ENTLA+IDA+a+b+Gx+Gy+pubkey).lower())
        M1 = ZA + hex_zfill(plain_text.encode("utf-8").hex()) # B3
        B4 = bytes_sm3(M1)
        return int(B4, 16)
    
    def _B5B6B7(self, R: str, S: str, pubkey: str, B4: int):
        B5: int = int_mod((int(R,16)+int(S,16)), self.elliptic_curve.n) # B5
        if B5 == 0: return False
        sG = kG(int(S,16), "%64x%64x" % (self.elliptic_curve.G[0], self.elliptic_curve.G[1]), LEN_PARA)
        tPA = kG(B5, pubkey, LEN_PARA)
        B6: List[int] = PointCalculate(SM2EllipticCurve).plus_point([int(sG[:64], 16), int(sG[64:], 16)], [int(tPA[:64], 16), int(tPA[64:], 16)])
        B7: int = int_mod((B4+B6[0]), self.elliptic_curve.n)
        return True if B7 == int(R, 16) else False