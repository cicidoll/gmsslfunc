from typing import Dict
import unittest, sys
sys.path.append('.')

from SM2Key.SM2KeyCreate import calculate_public_key

test_data_1: Dict[str, str] = {
    "pk": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "sk": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}
test_data_2: Dict[str, str] = {
    "pk": "08F83B4270A87139B4F295245D80E377684F8FB4B108DE5D03D088FAE67CCC4AA9C1477E3A6768CC2354479CC4ECE6ADB5E80F019E3D236C6C5BE17B05152644",
    "sk": "4E2DFC42732666E21C2952C8424190F61FEDA2A384D2CDB18CD13277462D443E"
}

class TestDerIBase(unittest.TestCase):

    def test_data_1(self):
        """ 测试公私钥 """
        pk_data = calculate_public_key(test_data_1["sk"])
        self.assertEqual(pk_data, test_data_1["pk"])

    def test_data_2(self):
        """ 测试公私钥 """
        pk_data = calculate_public_key(test_data_2["sk"])
        self.assertEqual(pk_data, test_data_2["pk"].lower())

if __name__ == "__main__":
    unittest.main()