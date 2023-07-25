# from fractions import Fraction

# private_key = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"
# temp1 =  1 + int(private_key, 16)
# print(hex(temp1))
# # temp = Fraction(1,)

# # print(int(temp))


a = 1
b = 2
c = 3

def afunc(a):
    return a*2

d, e, f = map(afunc, (a, b, c))

print([d, e, f])