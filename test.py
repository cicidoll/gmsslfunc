from utils.StringConvert import StringConvert

def calculation_length(value) -> None:
    """ 计算长度 """
    value_len: int = int(len(value) / 2) # 计算Value字段占用的字节数
    if value_len < 128:
        length = hex(value_len).replace("0x", "").zfill(2) # 用一个字节完成Length值
    elif value_len >= 128:
        length_value: str = StringConvert.int_convert_hex(value_len)
        length_flag: str = StringConvert.bin_convert_hex("1"+bin(int(len(length_value)/2)).replace("0b", "").zfill(7))
        length = length_flag + length_value

    return length
    
data = "43" *127

print(calculation_length(data))

data = "54" *129

print(calculation_length(data))

data = "54" *160

print(calculation_length(data))