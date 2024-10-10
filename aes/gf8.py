
def byte(x, n=8):
    return format(x, f"0{n}b")

def int16(x):
    return int(x, 16)

def gf8_multiple(a, b):
    a = int16(a)
    b = int16(b)
    tmp = 0
    b_byte = bin(b)[2:]
    for i in range(len(b_byte)):
        tmp = tmp ^ (int(b_byte[-(i+1)]) * (a << i))

    mod = int("100011011", 2)
    exp = len(bin(tmp)[2:])
    diff =  exp - len(bin(mod)[2:]) + 1

    for i in range(diff):
        if byte(tmp, exp)[i] == "1":
            tmp = tmp ^ (mod << diff - i - 1)
    return str(hex(tmp)[2:].upper())

def gf8_plus(a: str, b: str) -> str:
    a = int16(a)
    b = int16(b)
    tmp = a ^ b
    result = str(hex(tmp)[2:].upper())
    if len(result) == 1:
        result = '0' + result
    return result



# while True:
#     a = input("Nhập a: ")
#     b = input("Nhập b: ")
#     print(f"a * b = {gf8_multiple(a, b)}")
    

# while True:
#     a = input("Nhập a: ")
#     b = input("Nhập b: ")
#     print(f"a + b = {gf8_plus(a, b)}")