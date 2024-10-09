from table import *


def text_to_hex(text):
    """Chuyển đổi một chuỗi văn bản thành chuỗi hexadecimal."""
    return int.from_bytes(text.encode('utf-8'), byteorder='big')

def text_to_matrix(text, convert_to_hex: bool = True):
    """Chuyển đổi giá trị văn bản thành ma trận 4x4 byte."""
    if convert_to_hex:
        text = text_to_hex(text)
    matrix = [[0] * 4 for _ in range(4)]
    for row in range(4):
        for col in range(4):
            shift_amount = (15 - (row * 4 + col)) * 8
            matrix[row][col] = (text >> shift_amount) & 0xFF
    return matrix

def matrix_to_text(matrix):
    """Chuyển đổi ma trận 4x4 byte thành giá trị văn bản."""
    text = 0
    for row in range(4):
        for col in range(4):
            shift_amount = (15 - (row * 4 + col)) * 8
            text |= (matrix[row][col] << shift_amount)
    return text


def generate_round_keys(key):
    round_keys = text_to_matrix(key)
    for i in range(4, 4 * 11):
        round_keys.append([])
        if i % 4 == 0:
            byte = round_keys[i - 4][0] ^ Sbox[round_keys[i - 1][1]] ^ Rcon[int(i / 4)]
            round_keys[i].append(byte)
            for j in range(1, 4):
                byte = round_keys[i - 4][j] ^ Sbox[round_keys[i - 1][(j + 1) % 4]]
                round_keys[i].append(byte)
        else:
            for j in range(4):
                byte = round_keys[i - 4][j] ^ round_keys[i - 1][j]
                round_keys[i].append(byte)
    return round_keys

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]
            
def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = Sbox[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = InvSbox[s[i][j]]
            
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    
def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
        
def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v


def round_encrypt(state_matrix, key_matrix):
    sub_bytes(state_matrix)
    shift_rows(state_matrix)
    mix_columns(state_matrix)
    add_round_key(state_matrix, key_matrix)
    
def round_decrypt(state_matrix, key_matrix):
    add_round_key(state_matrix, key_matrix)
    inv_mix_columns(state_matrix)
    inv_shift_rows(state_matrix)
    inv_sub_bytes(state_matrix)
    
def encrypt(plaintext, round_keys):
    plain_state = text_to_matrix(plaintext)
    add_round_key(plain_state, round_keys[:4])
    for i in range(1, 10):
        round_encrypt(plain_state, round_keys[4 * i : 4 * (i + 1)])
        print('Round: ', i)
        print(plain_state)
    sub_bytes(plain_state)
    shift_rows(plain_state)
    add_round_key(plain_state, round_keys[40:])
    return matrix_to_text(plain_state)

def decrypt(ciphertext, round_keys, convert_to_hex = True):
    cipher_state = text_to_matrix(ciphertext, convert_to_hex)
    add_round_key(cipher_state, round_keys[40:])
    inv_shift_rows(cipher_state)
    inv_sub_bytes(cipher_state)
    for i in range(9, 0, -1):
        round_decrypt(cipher_state, round_keys[4 * i : 4 * (i + 1)])
        print('Round: ', i)
        print(cipher_state)
    add_round_key(cipher_state, round_keys[:4])
    return matrix_to_text(cipher_state)

def encrypt_gui(plaintext, key):
    round_keys = generate_round_keys(key)
    print(round_keys)
    
    return encrypt(plaintext, round_keys)

def decrypt_gui(encrypt_text, key):
    round_keys = generate_round_keys(key)
    print(round_keys)
    
    print(encrypt_text)
    return decrypt(encrypt_text, round_keys)
    

def main():
    plain_text = "Two One Nine Two"
    key = "Thats my Kung Fu"
    
    # round_keys = generate_round_keys(key)
    # print(round_keys)
    
    # encrypt_text = encrypt(plain_text, round_keys)
    # print(encrypt_text)
    
    # decrypt_text = decrypt(encrypt_text, round_keys, convert_to_hex=False)
    # print(decrypt_text)


main()