import unittest, sys
sys.path.append('.')

from SM2Key import calculate_public_key

test_data_1: dict = {
    "pk": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "sk": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}

class TestDerIBase(unittest.TestCase):

    def test_data_1(self):
        """ 测试公私钥 """
        pk_data = calculate_public_key(test_data_1["sk"])
        self.assertEqual(pk_data, test_data_1["pk"])

if __name__ == "__main__":
    unittest.main()