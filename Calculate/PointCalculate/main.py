from Calculate.EllipticCurve.IBase import EllipticCurveIBase
from Calculate.ModCalculate import int_mod, decimal_mod
from typing import List
import math

class PointCalculate:
    """ 倍点计算 """
    elliptic_curve: EllipticCurveIBase

    def __init__(self, elliptic_curve: EllipticCurveIBase) -> None:
        # 初始化椭圆曲线参数
        self.elliptic_curve = elliptic_curve

    def muly_point(self, n: int, P: List[int]) -> List[int]:
        """ 多倍点计算
            n为十进制，表示标量乘法相乘次数
            P为基点
            返回的坐标为十进制整数
        """
        # 快速指数运算
        n_0b = bin(n).replace('0b', '')
        i = len(n_0b) - 1
        # Q为计算结果
        Q: List[int, int] = P
        if i > 0:
            n = n - 2**i
            while i > 0:
                Q = self.plus_point(Q, Q)
                i -= 1
            if n > 0:
                Q = self.plus_point(Q, self.muly_point(n, P))
        return Q

    def plus_point(self, P: List[int], Q: List[int]) -> List[int]:
        """ 双倍点运算 """
        # 获取SM2椭圆方程参数
        a: int = self.elliptic_curve.a
        p: int = self.elliptic_curve.p
        # 开始运算(~ 按位取反运算符：对数据的每个二进制位取反,即把1变为0,把0变为1 )
        if (math.isinf(P[0]) or math.isinf(P[1])) and (~math.isinf(Q[0]) and ~math.isinf(Q[1])):
            # OP = P
            R = Q
        elif (~math.isinf(P[0]) and ~math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):
            # PO = P
            R = P
        elif (math.isinf(P[0]) or math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):
            # OO = O
            R = [float('inf'), float('inf')]
        else:
            if P != Q:
                # 当P!=Q时，计算PQ直线斜率m=(y2-y1)/(x2-x1)
                m = decimal_mod(Q[1]-P[1], Q[0]-P[0], p)
            else:
                # 当P=Q时，计算PQ直线斜率m
                m = decimal_mod(3*P[0]**2+a, 2*P[1], p)
            x = int_mod(m**2-P[0]-Q[0], p)
            y = int_mod(m*(P[0]-x)-P[1], p)
            R = [x, y]
        return R