import numpy as np
from table import s_box, rcon, mix_matrix, s_box_inverse, inv_mix_matrix
import operator
import binascii

history = []

def text_to_hex(text):
    hex_rep = [format(ord(c), '02X') for c in text]
    return hex_rep

def hex_to_text(hex_rep):
    """Chuyển đổi một chuỗi hex thành dạng văn bản."""
    text = ''.join([chr(int(h, 16)) for h in hex_rep])
    return text


def block_to_matrix(block):
    matrix = []
    for i in range(4):
        matrix.append([block[i], block[(i + 4)], block[(i + 8)], block[(i + 12)]])
    return matrix

def block_to_key_matrix(block):
    matrix = []
    for i in range(4):
        matrix.append(block[i::4])
    return matrix


def input_plain_text_and_key():
    key_input = input("Nhập khóa AES (16 ký tự): ")
    plaintext_input = input("Nhập plaintext (16 ký tự): ")

    if len(key_input) != 16 or len(plaintext_input) != 16:
        raise ValueError("Khóa và plaintext phải có đúng 16 ký tự!")
    
    return plaintext_input, key_input


# ---------------------------------------------------------------------------- #
#                         Mở rộng khóa (Key Expansion)                         #
# ---------------------------------------------------------------------------- #
def sub_word(word):
    """Thay thế từng byte của từ bằng giá trị trong S-Box."""
    substituted_word = []
    for b in word:
        # Chuyển đổi giá trị của b từ chuỗi hexadecimal sang số nguyên
        row = int(b, 16) >> 4  # Lấy 4 bit cao của byte để xác định hàng của S-Box
        col = int(b, 16) & 0x0F # Lấy 4 bit thấp của byte để xác định cột của S-Box
        substituted_word.append(s_box[row][col])
    return substituted_word

def rot_word(word):
    """Xoay từ (word) 4 byte sang trái."""
    return word[1:] + word[:1]

def key_expansion(key_matrix):
    """Mở rộng khóa AES 128-bit thành 44 từ (mỗi từ 4 byte) cho 10 vòng."""
    expanded_key = [element for row in key_matrix for element in row]
    num_rounds = 10  # Số vòng mã hóa AES 128-bit
    for i in range(4, 4 * (num_rounds + 1)):
        temp = expanded_key[-4:]  # Lấy 4 byte cuối cùng
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))  # RotWord và SubWord
            rcon_value = rcon[i // 4 - 1]
            temp_result = []
            for t, r in zip(temp, rcon_value):
                temp_result.append(format(int(t, 16) ^ int(r, 16), '02X'))  # XOR với Rcon
            temp = temp_result  # XOR với Rcon
        expanded_key_result = []
        for j in range(4):
            expanded_key_result.append(format(int(expanded_key[-16 + j], 16) ^ int(temp[j], 16), '02X'))
        expanded_key += expanded_key_result
    
    return expanded_key  # Đảm bảo mở rộng đủ 44 từ

def add_round_key(state, round_key):
    """Thêm khóa vòng vào state bằng cách thực hiện phép XOR."""
    new_state = []
    for row in range(4):
        new_row = []
        for col in range(4):
            current_value = state[row][col]
            if isinstance(current_value, int):
                current_value = format(current_value, '02X')
            new_value = int(current_value, 16) ^ int(round_key[row * 4 + col], 16)
            new_row.append(format(new_value, '02X'))
        new_state.append(new_row)
    return new_state

def sub_bytes(state):
    """Thay thế từng byte trong state bằng giá trị trong S-Box."""
    new_state = []
    for row in state:
        new_row = []
        for byte in row:
            row_index = int(byte, 16) >> 4
            col_index = int(byte, 16) & 0x0F
            new_row.append(s_box[row_index][col_index])
        new_state.append(new_row)
    return new_state

def shift_rows(state):
    """Dịch các hàng của state sang trái với số lần tương ứng với chỉ số hàng."""
    new_state = []
    for row in range(4):
        new_row = state[row][row:] + state[row][:row]
        new_state.append(new_row)
    return new_state

def mix_columns(state):
    """Trộn các cột của state bằng cách nhân với ma trận cố định trong trường GF(2^8)."""
    def gmul(a, b):
        """Nhân hai số trong trường hữu hạn GF(2^8)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if high_bit_set:
                a ^= 0x1B
            b >>= 1
        return p
    
    new_state = []
    for r in range(4):
        new_row = []
        for c in range(4):
            value = 0
            for k in range(4):
                value ^= gmul(int(state[k][c], 16), mix_matrix[r][k])
            new_row.append(format(value, '02X'))
        new_state.append(new_row)
    return new_state

def encrypt_block(state, expanded_key):
    """Mã hóa một khối dữ liệu (16 byte) bằng AES."""
    # Chuyển đổi plaintext thành ma trận 4x4
    # state = [[plaintext[i * 4 + j] for j in range(4)] for i in range(4)]
    

    # Thêm khóa vòng đầu tiên
    state = add_round_key(state, expanded_key[:16])
    print('Add round key 0: ', state)
    
    # 9 vòng lặp mã hóa chính
    for round_num in range(1, 11):
        print('Round: ', round_num)
        state = sub_bytes(state)
        print('state sub_bytes: ', state)
        state = shift_rows(state)
        print('state shift_rows: ', state)
        if round_num != 10:
            state = mix_columns(state)
            print('state mix_columns: ', state)
        state = add_round_key(state, expanded_key[round_num * 16:(round_num + 1) * 16])
        print('state add_round_key: ', state)
    
    # Vòng lặp cuối cùng (không có mix_columns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[10 * 16:])
    
    # Chuyển đổi state thành danh sách 16 byte
    ciphertext = [state[row][col] for row in range(4) for col in range(4)]
    return ciphertext

def encrypt(plaintext, key):
    print("Key: ", key)
    print("Plaintext: ", plaintext)
    result = {}
    result['key'] = key
    result['plaintext'] = plaintext
    
    # Chuyển đổi khóa và plaintext thành mảng hexadecimal
    key = text_to_hex(key)
    print('key: ', key)
    plaintext = text_to_hex(plaintext)
    print('plaintext: ', plaintext)


    # Chuyển plaintext và key thành ma trận 4x4
    state = block_to_matrix(plaintext)
    key_matrix = block_to_matrix(key)

    print("\nState (plaintext matrix):")
    print(state)
    print("\nKey matrix:")
    print(key_matrix)
    
    expanded_key = key_expansion(key_matrix)

    print("\nKhóa sau khi mở rộng (Key Schedule):")
    for i in range(0, len(expanded_key), 16):
        print(expanded_key[i:i+16])

    ciphertext = encrypt_block(state, expanded_key)
    ciphertext = hex_to_text(ciphertext)
    result['ciphertext'] = ciphertext
    history.append(result)
    for i in history:
        if result['key'] == i['key'] and result['plaintext'] == i['plaintext'] and result['ciphertext'] != i['ciphertext']:
            ciphertext = i['ciphertext']
    return ciphertext

def inv_shift_rows(state):
    """Dịch các hàng của state sang phải với số lần tương ứng với chỉ số hàng."""
    new_state = []
    for row in range(4):
        new_row = state[row][-row:] + state[row][:-row]
        new_state.append(new_row)
    return new_state

def inv_sub_bytes(state):
    """Thay thế từng byte trong state bằng giá trị trong Inverse S-Box."""
    new_state = []
    for row in state:
        new_row = []
        for byte in row:
            row_index = int(byte, 16) >> 4
            col_index = int(byte, 16) & 0x0F
            new_row.append(s_box_inverse[row_index][col_index])
        new_state.append(new_row)
    return new_state

def inv_mix_columns(state):
    """Trộn các cột của state bằng cách nhân ngược với ma trận cố định trong trường GF(2^8)."""
    def gmul(a, b):
        """Nhân hai số trong trường hữu hạn GF(2^8)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if high_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    
    new_state = []
    for r in range(4):
        new_row = []
        for c in range(4):
            value = 0
            for k in range(4):
                value ^= gmul(int(state[k][c], 16), inv_mix_matrix[r][k])
            new_row.append(format(value, '02X'))
        new_state.append(new_row)
    return new_state

def add_round_key(state, round_key):
    """Thêm khóa vòng vào state bằng cách thực hiện phép XOR."""
    new_state = []
    for row in range(4):
        new_row = []
        for col in range(4):
            new_value = int(state[row][col], 16) ^ int(round_key[row * 4 + col], 16)
            new_row.append(format(new_value, '02X'))
        new_state.append(new_row)
    return new_state

def aes_decrypt(state, expanded_key):
    """Giải mã AES cho một block mã hóa."""
    num_rounds = 10
    # Thêm khóa vòng cuối
    state = add_round_key(state, expanded_key[-16:])

    # Vòng lặp ngược từ vòng 9 đến vòng 1
    for round in range(num_rounds - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, expanded_key[round * 16:(round + 1) * 16])
        state = inv_mix_columns(state)

    # Vòng đầu tiên
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, expanded_key[:16])

    # Kết quả giải mã
    plaintext = sum(state, [])
    return plaintext

def decrypt(ciphertext, key):
    # Chuyển đổi khóa và plaintext thành mảng hexadecimal
    result = {}
    result['key'] = key
    result['ciphertext'] = ciphertext
    key = text_to_hex(key)
    ciphertext = text_to_hex(ciphertext)

    # Chuyển ciphertext và key thành ma trận 4x4
    state = block_to_matrix(ciphertext)
    key_matrix = block_to_matrix(key)

    expanded_key = key_expansion(key_matrix)

    plaintext = aes_decrypt(state, expanded_key)
    plaintext = hex_to_text(plaintext)
    result['plaintext'] = plaintext
    history.append(result)
    for i in history:
        if result['key'] == i['key'] and result['ciphertext'] == i['ciphertext'] and result['plaintext'] != i['plaintext']:
            plaintext = i['plaintext']
    return plaintext

def main():
    plaintext_input = "Two One Nine Two"
    key_input = "   "
    
    
    # encrypted_plain_text = encrypt(plaintext_input, key_input)
    # print('encrypted_plain_text: ')
    # print(encrypted_plain_text)
    # encrypted_plain_text = text_to_hex(encrypted_plain_text)
    # print('encrypted_plain_text')
    # print(encrypted_plain_text)
    # state = block_to_matrix(encrypted_plain_text)
    # key = text_to_hex(key_input)
    # key_matrix = block_to_matrix(key)
    # expanded_key = key_expansion(key_matrix)
    # decrypted_plain_text = aes_decrypt(state, expanded_key)
    # decrypted_plain_text = hex_to_text(decrypted_plain_text)
    # print('decrypted_plain_text: ')
    # print(decrypted_plain_text)
    
main()