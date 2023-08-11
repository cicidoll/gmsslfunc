from Sign import SM2withSM3SignDer, SM2withSM3VerifyDer

plain_text: str = "hello"
# 支持输入多种格式编码公钥：Hex编码Raw格式128长度、带04标识的Hex编码Raw格式130长度、Hex编码Der格式、Base64编码Der格式
public_key: dict = {
    "hex_raw_128": "439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "hex_raw_130": "04439a9932c2ff96330913b25c56638721ece87b872a92b2de26dc5844f4bc44adc33e05ebd7c983064effae045d78b15c1c451cf61d510457462acbf455ce5cf4",
    "base64_der": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQ5qZMsL/ljMJE7JcVmOHIezoe4cqkrLeJtxYRPS8RK3DPgXr18mDBk7/rgRdeLFcHEUc9h1RBFdGKsv0Vc5c9A==",
    "hex_der": "3059301306072A8648CE3D020106082A811CCF5501822D03420004439A9932C2FF96330913B25C56638721ECE87B872A92B2DE26DC5844F4BC44ADC33E05EBD7C983064EFFAE045D78B15C1C451CF61D510457462ACBF455CE5CF4"
}
# 支持输入多种格式编码私钥：Hex编码Raw格式64长度、Base64编码Der格式(GMT0010-2012)、Hex编码Der格式(GMT0010-2012)
private_key: dict = {
    "base64_der": "MHcCAQEEIOhn1+EuZCI7LlHF4TpESJRbRAsTL3oi2GIx/9khOnz7oAoGCCqBHM9VAYItoUQDQgAEQ5qZMsL/ljMJE7JcVmOHIezoe4cqkrLeJtxYRPS8RK3DPgXr18mDBk7/rgRdeLFcHEUc9h1RBFdGKsv0Vc5c9A==",
    "hex_der": "30770201010420E867D7E12E64223B2E51C5E13A4448945B440B132F7A22D86231FFD9213A7CFBA00A06082A811CCF5501822DA14403420004439A9932C2FF96330913B25C56638721ECE87B872A92B2DE26DC5844F4BC44ADC33E05EBD7C983064EFFAE045D78B15C1C451CF61D510457462ACBF455CE5CF4",
    "hex_raw": "e867d7e12e64223b2e51c5e13a4448945b440b132f7a22d86231ffd9213a7cfb"
}

""" 输出输入Der格式Base64编码签名值 Start """

# 签名值
signed_text = SM2withSM3SignDer(
    private_key["base64_der"],
    public_key["hex_raw_128"]
    ).sign(
        plain_text,
        asn1_der=True
    )

print("需要签名的原文值：%s" % plain_text)
print("签名值是：%s" % signed_text)

# 验签结果
verify_flag: bool = SM2withSM3VerifyDer().verify(
    plain_text = plain_text,
    signed_text = signed_text,
    public_key = public_key["hex_der"],
    asn1_der=True
)
print("验签结果：%s" % verify_flag)

""" 输出输入Der格式Base64编码签名值 End """

""" 输出输入Raw格式Hex编码签名值 Start """

signed_text = SM2withSM3SignDer(private_key["hex_raw"]).sign(plain_text)

print("需要签名的原文值：%s" % plain_text)
print("签名值是：%s" % signed_text)

# 验签结果
verify_flag: bool = SM2withSM3VerifyDer().verify(
    plain_text = plain_text,
    signed_text = signed_text,
    public_key = public_key["base64_der"]
)
print("验签结果：%s" % verify_flag)

""" 输出输入Raw格式Hex编码签名值 End """