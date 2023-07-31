from Sign.sm2withsm3 import SM2withSM3Sign, SM2withSM3Verify

# 签名
test_data: dict = {
    "plain_text": "hello",
    "public_key": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "private_key": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}

# 签名值
signed_text = SM2withSM3Sign(
    test_data["private_key"],
    test_data["public_key"]
    ).sign(
        test_data["plain_text"],
        asn1_der=True
    )

print(signed_text)

# 验签结果
verify_flag: bool = SM2withSM3Verify().verify(
    plain_text=test_data["plain_text"],
    signed_text = signed_text,
    pubkey = test_data["public_key"],
    asn1_der=True
)

print(verify_flag)