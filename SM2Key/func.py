from Calculate.EllipticCurve import SM2EllipticCurve, TestSM2EncryptEllipticCurve
from Calculate.PointCalculate import PointCalculate

# 根据SM2私钥计算SM2公钥 :params privkey 16进制私钥
calculate_public_key: str = lambda privkey: "".join([ hex(i).replace("0x", "").zfill(64) for i in PointCalculate(SM2EllipticCurve).muly_point(int(privkey, 16), SM2EllipticCurve.G)])
# GB/T 32918.2-2016-《SM2椭圆曲线公钥密码算法.pdf》 P57-附录A
test_sign_calculate_public_key: str = lambda privkey: "".join([ hex(i).replace("0x", "").zfill(64) for i in PointCalculate(TestSM2EncryptEllipticCurve).muly_point(int(privkey, 16), TestSM2EncryptEllipticCurve.G)])