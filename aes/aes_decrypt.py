from table import inv_mix_matrix, inv_s_box
from gf8 import gf8_plus, gf8_multiple
from key import generate_key_schedule

def transpose_matrix(matrix):
    # Sử dụng zip(*matrix) để hoán đổi hàng và cột
    transposed_matrix = [list(row) for row in zip(*matrix)]
    return transposed_matrix


# Hàm inv_sub_bytes: Sử dụng inverse S-Box để thay thế các byte
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            row = int(byte[0], 16)
            col = int(byte[1], 16)
            state[i][j] = inv_s_box[row][col]
    return state

# Hàm inv_shift_rows: Dịch các hàng ngược lại so với shift_rows
def inv_shift_rows(state):
    # Hàng đầu tiên giữ nguyên
    # Hàng thứ 2 dịch 1 byte sang phải
    state[1] = state[1][-1:] + state[1][:-1]  
    # Hàng thứ 3 dịch 2 byte sang phải
    state[2] = state[2][-2:] + state[2][:-2]  
    # Hàng thứ 4 dịch 3 byte sang phải
    state[3] = state[3][-3:] + state[3][:-3]  
    return state

# Hàm inv_mix_columns: Sử dụng ma trận inv_mix_matrix để thực hiện phép nhân trong GF(2^8)
def inv_mix_columns(state):
    state = transpose_matrix(state)
    for i in range(4):
        a = state[i].copy()
        state[i][0] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('0E', a[0]), 
                                                  gf8_multiple('0B', a[1])), 
                                                  gf8_multiple('0D', a[2])), 
                                                  gf8_multiple('09', a[3]))
        state[i][1] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('09', a[0]), 
                                                  gf8_multiple('0E', a[1])), 
                                                  gf8_multiple('0B', a[2])), 
                                                  gf8_multiple('0D', a[3]))
        state[i][2] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('0D', a[0]), 
                                                  gf8_multiple('09', a[1])), 
                                                  gf8_multiple('0E', a[2])), 
                                                  gf8_multiple('0B', a[3]))
        state[i][3] = gf8_plus(gf8_plus(gf8_plus(gf8_multiple('0B', a[0]), 
                                                  gf8_multiple('0D', a[1])), 
                                                  gf8_multiple('09', a[2])), 
                                                  gf8_multiple('0E', a[3]))
    state = transpose_matrix(state)
    return state

# Hàm AddRoundKey: XOR khối dữ liệu với khóa con tương ứng
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] = gf8_plus(state[i][j], round_key[i][j])
    return state

def aes_decrypt_round(state, round_key, mix_columns_needed=True):
    # Bước 1: Inverse ShiftRows (dịch các hàng ngược lại)
    state = inv_shift_rows(state)
    print(f"State after Inverse ShiftRows: {state}")
    
    # Bước 2: Inverse SubBytes (sử dụng Inverse S-Box)
    state = inv_sub_bytes(state)
    print(f"State after Inverse SubBytes: {state}")
    
    # Bước 3: AddRoundKey (XOR với round key)
    state = add_round_key(state, round_key)
    print(f"State after AddRoundKey: {state}")
    
    # Bước 4: Inverse MixColumns (nếu cần)
    if mix_columns_needed:
        state = inv_mix_columns(state)
        print(f"State after Inverse MixColumns: {state}")
    return state


def ciphertext_to_matrix(ciphertext):
    # Kiểm tra độ dài ciphertext
    if len(ciphertext) != 32:
        raise ValueError("Ciphertext phải có độ dài chính xác 32 ký tự (128-bit).")

    # Chia ciphertext thành các từ 32-bit (mỗi từ là 4 byte)
    matrix = []
    for i in range(4):
        word = ciphertext[i*8:(i+1)*8]
        result = [word[j:j+2] for j in range(0, len(word), 2)]
        matrix.append(result)
    return matrix


# Hàm thực hiện toàn bộ 10 vòng mã hóa AES
def aes_decrypt(ciphertext, key):
    key_schedule = generate_key_schedule(key)
    ciphertext_matrix = ciphertext_to_matrix(ciphertext)
    ciphertext_matrix = transpose_matrix(ciphertext_matrix)
    print(f"\n\nInitial state: {ciphertext_matrix}")
    
    # Bước 1: AddRoundKey với khóa con của vòng cuối cùng (vòng 10)
    state = add_round_key(ciphertext_matrix, key_schedule[10])
    print(f"\n\nState after initial AddRoundKey: {state}")
    
    # Thực hiện 9 vòng giải mã tiếp theo
    for round_num in range(9, 0, -1):
        print(f"Round {round_num}")
        state = aes_decrypt_round(state, key_schedule[round_num], inv_s_box)
        print(f"State after round {round_num}: {state} \n\n")

    # Vòng cuối cùng (chỉ có AddRoundKey, Inverse ShiftRows, Inverse SubBytes)
    print("Final 0")
    state = aes_decrypt_round(state, key_schedule[0], mix_columns_needed=False)

    # Chuyển đổi ma trận thành dạng chuỗi
    state = transpose_matrix(state)
    decrypted_text = ''.join([chr(int(byte, 16)) for row in state for byte in row])

    return decrypted_text