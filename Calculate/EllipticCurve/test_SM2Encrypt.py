from .IBase import EllipticCurveIBase

class TestSM2EncryptEllipticCurve(EllipticCurveIBase):
    """ SM2算法-非对称加解密类使用的参数(对应附录A中的测试参数)
        使用素数域256位椭圆曲线
        椭圆曲线方程y^2 = x^3 + ax + b
    """
    # 素数域大小
    p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    # 椭圆曲线系数a
    a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    # 椭圆曲线系数b
    b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    # 子群的阶
    n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
    # 生成子群的基点G的x坐标
    _Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    # 生成子群的基点G的y坐标
    _Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

    # 生成子群的基点G
    G = [_Gx, _Gy]