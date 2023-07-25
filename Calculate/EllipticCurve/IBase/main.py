class EllipticCurveIBase:
    """ 椭圆曲线方程类
            方程y^2 = x^3 + ax + b
    """
    # 素数域大小
    p: int
    # 椭圆曲线系数a
    a: int
    # 椭圆曲线系数b
    b: int
    # 子群的阶
    n: int
    # 生成子群的基点G的x坐标
    _Gx: int = None
    # 生成子群的基点G的y坐标
    _Gy: int = None

    # 生成子群的基点G
    G = [_Gx, _Gy]