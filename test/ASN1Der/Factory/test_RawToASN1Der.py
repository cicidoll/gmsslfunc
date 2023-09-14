import unittest, sys
sys.path.append('.')

from ASN1Der.Object.RawToASN1DerObject import BitString, Sequence, Oid
from ASN1Der.Factory.RawToASN1Der import RawToASN1DerObjectFactory
from ASN1Der import ASN1DerObjectTagsEnum

class TestRawToASN1Der(unittest.TestCase):

    def test_127_data(self):
        """ 测试长度127字节的数据-Sequence类型 """
        # 测试长度127字节的Sequence数据
        data_127 = "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        assert_127_result = {
            "raw_value": "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "tag": ASN1DerObjectTagsEnum.Sequence.value,
            "length": "59",
            "value": "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "hex_raw_value": "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        }
        # 开始测试
        test: Sequence = RawToASN1DerObjectFactory.create_der_object(assert_127_result["raw_value"], assert_127_result["tag"])
        self.assertEqual(test.tag, assert_127_result["tag"])
        self.assertEqual(test.length, assert_127_result["length"])
        self.assertEqual(test.value, assert_127_result["value"])
        self.assertEqual(test.get_hex_der(), data_127)

    def test_129_data(self):
        """ 测试长度129字节的数据 """
        # 测试长度129字节的数据
        assert_129_result = {
            "hex_raw_value": "47eb995adf9e700dfba73132c15f5c24c2e0bfc624af15660eb86a2eab2bc4971fe3cbdc63a525ecc7b428616636a1311bbfddd0fcbf1794901de55ec7115ec9559feba33e14c799a6cbbaa1460f39d444c4c84b760e205d6da9349ed4d58742eb2426511490b40f065e5288327a9520a0fdf7e57d60dd72689bf57b058f6d1e",
            "tag": ASN1DerObjectTagsEnum.BitString.value,
            "length": "8181",
            "value": "0047eb995adf9e700dfba73132c15f5c24c2e0bfc624af15660eb86a2eab2bc4971fe3cbdc63a525ecc7b428616636a1311bbfddd0fcbf1794901de55ec7115ec9559feba33e14c799a6cbbaa1460f39d444c4c84b760e205d6da9349ed4d58742eb2426511490b40f065e5288327a9520a0fdf7e57d60dd72689bf57b058f6d1e",
            "hex_der": "0381810047eb995adf9e700dfba73132c15f5c24c2e0bfc624af15660eb86a2eab2bc4971fe3cbdc63a525ecc7b428616636a1311bbfddd0fcbf1794901de55ec7115ec9559feba33e14c799a6cbbaa1460f39d444c4c84b760e205d6da9349ed4d58742eb2426511490b40f065e5288327a9520a0fdf7e57d60dd72689bf57b058f6d1e"
        }
        # 开始测试
        test: BitString = RawToASN1DerObjectFactory.create_der_object(assert_129_result["hex_raw_value"], assert_129_result["tag"])
        self.assertEqual(test.tag, assert_129_result["tag"])
        self.assertEqual(test.length, assert_129_result["length"])
        self.assertEqual(test.value, assert_129_result["value"])
        self.assertEqual(test.get_hex_der(), assert_129_result["hex_der"])

    def test_Sequence_data(self):
        """ 测试长度127字节的数据-Sequence类型 """
        # 测试长度127字节的Sequence数据
        der_all_in_one = {
            "hex_raw_value": "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "tag": ASN1DerObjectTagsEnum.Sequence.value,
            "length": "59",
            "value": "301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "hex_der": "3059301306072A8648CE3D020106082A811CCF5501822D034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        }
        sub_der_1: dict = {
            "hex_raw_value": "06072A8648CE3D020106082A811CCF5501822D",
            "tag": ASN1DerObjectTagsEnum.Sequence.value,
            "length": "13",
            "value": "06072A8648CE3D020106082A811CCF5501822D",
            "hex_der": "301306072A8648CE3D020106082A811CCF5501822D"
        }
        sub_der_1_1: dict = {
            "hex_raw_value": "2A8648CE3D0201",
            "tag": ASN1DerObjectTagsEnum.Oid.value,
            "length": "07",
            "value": "2A8648CE3D0201",
            "hex_der": "06072A8648CE3D0201"
        }
        sub_der_1_2: dict = {
            "hex_raw_value": "2A811CCF5501822D",
            "tag": ASN1DerObjectTagsEnum.Oid.value,
            "length": "08",
            "value": "2A811CCF5501822D",
            "hex_der": "06082A811CCF5501822D"
        }
        sub_der_2: dict = {
            "hex_raw_value": "046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "tag": ASN1DerObjectTagsEnum.BitString.value,
            "length": "42",
            "value": "00046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11",
            "hex_der": "034200046A826E79032BA6144FA1EB22F4F2BA3D2B77EBDC54789C1EF15B64FBCFE7A259E771DDD2FE6DDB377B1A9820B394F58AFA2BF02226EC5DAEFACC14B2A22D4E11"
        }
        # 开始测试
        ## sub_der_1 拼装过程
        ### 实例化 sub_der_1_1
        sub_der_1_1_instance: Oid = RawToASN1DerObjectFactory.create_der_object(sub_der_1_1["hex_raw_value"], sub_der_1_1["tag"])
        self.assertEqual(sub_der_1_1_instance.tag, sub_der_1_1["tag"])
        self.assertEqual(sub_der_1_1_instance.length, sub_der_1_1["length"])
        self.assertEqual(sub_der_1_1_instance.value, sub_der_1_1["value"])
        self.assertEqual(sub_der_1_1_instance.get_hex_der(), sub_der_1_1["hex_der"])
        ### 实例化 sub_der_1_2
        sub_der_1_2_instance: Oid = RawToASN1DerObjectFactory.create_der_object(sub_der_1_2["hex_raw_value"], sub_der_1_2["tag"])
        self.assertEqual(sub_der_1_2_instance.tag, sub_der_1_2["tag"])
        self.assertEqual(sub_der_1_2_instance.length, sub_der_1_2["length"])
        self.assertEqual(sub_der_1_2_instance.value, sub_der_1_2["value"])
        self.assertEqual(sub_der_1_2_instance.get_hex_der(), sub_der_1_2["hex_der"])
        #### 拼装 sub_der_1
        sub_der_1_instance: Sequence = RawToASN1DerObjectFactory.create_sequence_object(sub_der_1_1_instance, sub_der_1_2_instance)
        self.assertEqual(sub_der_1_instance.tag, sub_der_1["tag"])
        self.assertEqual(sub_der_1_instance.length, sub_der_1["length"])
        self.assertEqual(sub_der_1_instance.value, sub_der_1["value"])
        self.assertEqual(sub_der_1_instance.get_hex_der(), sub_der_1["hex_der"])
        ## sub_der_2 拼装过程
        sub_der_2_instance: BitString = RawToASN1DerObjectFactory.create_der_object(sub_der_2["hex_raw_value"], sub_der_2["tag"])
        self.assertEqual(sub_der_2_instance.tag, sub_der_2["tag"])
        self.assertEqual(sub_der_2_instance.length, sub_der_2["length"])
        self.assertEqual(sub_der_2_instance.value, sub_der_2["value"])
        self.assertEqual(sub_der_2_instance.get_hex_der(), sub_der_2["hex_der"])
        ## der_all_in_one 拼装
        der_all_in_one_instance: Sequence = RawToASN1DerObjectFactory.create_sequence_object(sub_der_1_instance, sub_der_2_instance)
        self.assertEqual(der_all_in_one_instance.tag, der_all_in_one["tag"])
        self.assertEqual(der_all_in_one_instance.length, der_all_in_one["length"])
        self.assertEqual(der_all_in_one_instance.value, der_all_in_one["value"])
        self.assertEqual(der_all_in_one_instance.get_hex_der(), der_all_in_one["hex_der"])


if __name__ == "__main__":
    unittest.main()