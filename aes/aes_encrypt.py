from table import s_box
from gf8 import gf8_plus, gf8_multiple
from key import generate_key_schedule
from aes_decrypt import aes_decrypt

def transpose_matrix(matrix):
    # Sử dụng zip(*matrix) để hoán đổi hàng và cột
    transposed_matrix = [list(row) for row in zip(*matrix)]
    return transposed_matrix


def plaintext_to_matrix(plaintext):
    # Chuyển đổi khóa plain text thành các byte
    plaintext_bytes = plaintext.encode('utf-8')

    # Kiểm tra độ dài khóa, phải đủ 16 bytes cho AES-128
    if len(plaintext_bytes) != 16:
        raise ValueError("Plain text phải có độ dài chính xác 16 bytes (128-bit).")

    # Chia khóa thành các từ (mỗi từ là 4 byte)
    plaintext_matrix = []
    for i in range(4):
        word = plaintext_bytes[i*4:(i+1)*4]
        key_hex = word.hex()
        result = [key_hex[i:i+2] for i in range(0, len(key_hex), 2)]
        plaintext_matrix.append(result)

    return plaintext_matrix

# Hàm SubBytes: Thay thế từng byte dựa trên bảng S-box
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            row = int(byte[0], 16)
            col = int(byte[1], 16)
            state[i][j] = s_box[row][col]
    return state

# Hàm ShiftRows: Dịch chuyển các hàng của ma trận
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]  # Dòng thứ 2 dịch 1 byte sang trái
    state[2] = state[2][2:] + state[2][:2]  # Dòng thứ 3 dịch 2 byte sang trái
    state[3] = state[3][3:] + state[3][:3]  # Dòng thứ 4 dịch 3 byte sang trái
    return state

# Hàm MixColumns: Trộn các cột bằng cách nhân ma trận trong GF(2^8)
def mix_columns(state):
    state = transpose_matrix(state)
    for i in range(4):
        a = state[i].copy()
        state[i][0] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('02', a[0]), 
                                                 gf8_multiple('03', a[1])), 
                                                 gf8_multiple("01", a[2])), 
                                                 gf8_multiple("01", a[3]))
        state[i][1] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('01', a[0]), 
                                                 gf8_multiple('02', a[1])), 
                                                 gf8_multiple("03", a[2])), 
                                                 gf8_multiple("01", a[3]))
        state[i][2] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('01', a[0]), 
                                                 gf8_multiple('01', a[1])), 
                                                 gf8_multiple("02", a[2])), 
                                                 gf8_multiple("03", a[3]))
        state[i][3] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('03', a[0]), 
                                                 gf8_multiple('01', a[1])), 
                                                 gf8_multiple("01", a[2])), 
                                                 gf8_multiple("02", a[3]))
    state = transpose_matrix(state)
    return state

# Hàm AddRoundKey: XOR khối dữ liệu với khóa con tương ứng
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] = gf8_plus(state[i][j], round_key[i][j])
    return state

# Hàm thực hiện 1 vòng mã hóa AES
def aes_round(state, round_key, mix_columns_needed=True):
    state = sub_bytes(state)
    print(f"State after Inverse SubBytes: {state}")
    state = shift_rows(state)
    print(f"State after Inverse ShiftRows: {state}")
    if mix_columns_needed:
        state = mix_columns(state)
        print(f"State after Inverse MixColumns: {state}")
    state = add_round_key(state, round_key)
    print(f"State after AddRoundKey: {state}")
    return state

# Hàm thực hiện toàn bộ 10 vòng mã hóa AES
def aes_encrypt(plaintext, key):
    plaintext_matrix = plaintext_to_matrix(plaintext)
    plaintext_matrix = transpose_matrix(plaintext_matrix)
    key_schedule = generate_key_schedule(key)
    
    print(f"\n\nInitial state: {plaintext_matrix}")
    
    # AddRoundKey cho khóa đầu tiên
    state = add_round_key(plaintext_matrix, key_schedule[0])
    print(f"\n\nState after initial AddRoundKey: {state}")

    # Thực hiện 9 vòng đầu tiên
    for round_num in range(1, 10):
        print(f"Round {round_num}")
        state = aes_round(state, key_schedule[round_num])
        print(f"State after round {round_num}: {state} \n\n")

    # Vòng cuối cùng (không có MixColumns)
    print("Round 10")
    state = aes_round(state, key_schedule[10], mix_columns_needed=False)
    state = transpose_matrix(state)
    
    encrypted = ''.join([''.join(row) for row in state])
    return encrypted