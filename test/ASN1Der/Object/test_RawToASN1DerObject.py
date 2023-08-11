import unittest, sys
from typing import Dict
sys.path.append('.')

from ASN1Der import TagsEnum
from ASN1Der.Object.RawToASN1DerObject import RawToDerIBase, BitString, Oid, Sequence, INTEGER

class TestDerIBase(unittest.TestCase):

    def test_Sequence_data(self):
        """ 测试 Sequence-长度127字节 数据 """
        data = "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        result = {
            "tag": "30",
            "length": "59",
            "result": "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        }
        #  Sequence类型
        sequence: Sequence = Sequence(data)
        self.assertEqual(sequence.tag, result["tag"])
        self.assertEqual(sequence.length, result["length"])
        self.assertEqual(sequence.get_hex_raw(), data)
        self.assertEqual(sequence.get_hex_der(), result["result"])

    def test_Oid_7byte(self):
        """ 测试 Oid-长度7字节 数据"""
        data = "2A8648CE3D0201"
        result: Dict[str, str] = {
            "tag": "06",
            "length": "07",
            "result": "06072A8648CE3D0201"
        }
        # 开始测试
        oid: Oid = Oid(data)
        self.assertEqual(oid.tag, result["tag"])
        self.assertEqual(oid.length, result["length"])
        self.assertEqual(oid.get_hex_raw(), data)
        self.assertEqual(oid.get_hex_der(), result["result"])

    def test_INTEGER_21byte(self):
        """ 测试 INTEGER-长度21字节 数据"""
        data = "B9F068162CDAC12254DB7681DFF5F658C1381CE85912D454053B4D16259A3AC4"
        result: Dict[str, str] = {
            "tag": "02",
            "length": "21",
            "result": "022100B9F068162CDAC12254DB7681DFF5F658C1381CE85912D454053B4D16259A3AC4"
        }
        # 开始测试
        integer: INTEGER = INTEGER(data)
        self.assertEqual(integer.tag, result["tag"])
        self.assertEqual(integer.length, result["length"])
        self.assertEqual(integer.get_hex_raw(), data)
        self.assertEqual(integer.get_hex_der(), result["result"])

    def test_BitString_data_129(self):
        """ 测试 BitString-长度大于128字节 数据 """
        data = "47eb995adf9e700dfba73132c15f5c24c2e0bfc624af15660eb86a2eab2bc4971fe3cbdc63a525ecc7b428616636a1311bbfddd0fcbf1794901de55ec7115ec9559feba33e14c799a6cbbaa1460f39d444c4c84b760e205d6da9349ed4d58742eb2426511490b40f065e5288327a9520a0fdf7e57d60dd72689bf57b058f6d1e"
        result = {
            "tag": "03",
            "length": "8181",
            "result": "0381810047eb995adf9e700dfba73132c15f5c24c2e0bfc624af15660eb86a2eab2bc4971fe3cbdc63a525ecc7b428616636a1311bbfddd0fcbf1794901de55ec7115ec9559feba33e14c799a6cbbaa1460f39d444c4c84b760e205d6da9349ed4d58742eb2426511490b40f065e5288327a9520a0fdf7e57d60dd72689bf57b058f6d1e"
        }
        # 开始测试
        bit_string: BitString = BitString(data)
        self.assertEqual(bit_string.tag, result["tag"])
        self.assertEqual(bit_string.length, result["length"])
        self.assertEqual(bit_string.get_hex_raw(), data)
        self.assertEqual(bit_string.get_hex_der(), result["result"])

if __name__ == "__main__":
    unittest.main()