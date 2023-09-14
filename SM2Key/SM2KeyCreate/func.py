from Calculate.EllipticCurve import SM2EllipticCurve, TestSM2EncryptEllipticCurve
from Calculate.PointCalculate import PointCalculate, kG


# GB/T 32918.2-2016-《SM2椭圆曲线公钥密码算法.pdf》 P57-附录A
test_sign_calculate_public_key: str = lambda privkey: "".join([ hex(i).replace("0x", "").zfill(64) for i in PointCalculate(TestSM2EncryptEllipticCurve).muly_point(int(privkey, 16), TestSM2EncryptEllipticCurve.G)])

## 根据SM2私钥计算SM2公钥 :params privkey 16进制私钥 【多倍点计算-朴素运算】
#calculate_public_key: str = lambda privkey: "".join([ hex(i).replace("0x", "").zfill(64) for i in PointCalculate(SM2EllipticCurve).muly_point(int(privkey, 16), SM2EllipticCurve.G)])

# 根据SM2私钥计算SM2公钥 :params privkey 16进制私钥 【使用pysmx中的多倍点运算-加快计算速度】
LEN_PARA = 64
# calculate_public_key: str = lambda privkey: kG(int(privkey,16), "%64x%64x" % (SM2EllipticCurve.G[0], SM2EllipticCurve.G[1]), LEN_PARA)

def calculate_public_key(privkey: str) -> str:
    """
    根据SM2私钥计算SM2公钥 
    :params privkey 16进制私钥 【使用pysmx中的多倍点运算-加快计算速度
    :return: String类型 128长度的x+y
    """
    return kG(int(privkey,16), "%64x%64x" % (SM2EllipticCurve.G[0], SM2EllipticCurve.G[1]), LEN_PARA)