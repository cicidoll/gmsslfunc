from typing import Union
import math

class ModCalculate:
    """ 模运算 """

    @staticmethod
    def int_mod(a: int, b: int) -> Union[float, int]:
        """ 整数取模运算
            result = a mod b
        """
        if math.isinf(a):
            # 若a为无穷大 则结果为无穷
            return float('inf')
        else:
            return a % b

    @staticmethod
    def decimal_mod(a: int, b: int, p: int):
        """ 分数取模运算
            原式: 
                a/b = result mod p
            经过小费马定理转换可得:
                result = a * b^(p-2) mod p
        """
        if b == 0:
            result = float('inf')
        elif a == 0:
            result = 0
        else:
            # 快速指数运算: 时间复杂度O(log n)
            p_2_0b = bin(p-2).replace('0b', '')
            y = 1
            for i in range(len(p_2_0b)):
                # 小费马定理：a/b = result mod p => result = a*b^(p-2) mod p
                y = (y**2) % p
                if p_2_0b[i] == '1':
                    y = (y*b) % p
            result = (y*a)%p
        return result