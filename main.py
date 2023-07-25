from Sign.sm2withsm3 import SM2withSM3Sign, SM2withSM3Verify

# 签名
data: dict = {
    "plain_text": "hello",
    "public_key": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "private_key": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}

# 128长度hex格式签名值
signed_text = SM2withSM3Sign(data["private_key"], data["public_key"]).sign(data["plain_text"])


# 验签
verify_result: bool = SM2withSM3Verify().verify(plain_text=data["plain_text"], signed_text = signed_text, pubkey = data["public_key"])