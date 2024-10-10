from table import s_box, rcon
from gf8 import gf8_plus

def transpose_matrix(matrix):
    # Sử dụng zip(*matrix) để hoán đổi hàng và cột
    transposed_matrix = [list(row) for row in zip(*matrix)]
    return transposed_matrix

def text_to_key_schedule(plain_text_key):
    # Chuyển đổi khóa plain text thành các byte
    key_bytes = plain_text_key.encode('utf-8')

    # Kiểm tra độ dài khóa, phải đủ 16 bytes cho AES-128
    if len(key_bytes) != 16:
        raise ValueError("Khóa phải có độ dài chính xác 16 bytes (128-bit).")

    # Chia khóa thành các từ (mỗi từ là 4 byte)
    key_schedule = []
    for i in range(4):
        word = key_bytes[i*4:(i+1)*4]
        key_hex = word.hex()
        result = [key_hex[i:i+2] for i in range(0, len(key_hex), 2)]
        key_schedule.append(result)

    return key_schedule

# Hàm g thực hiện các bước Rotate, SubBytes và XOR với Rcon
def g(word: list, round_num: int):
    # Step 1: Rotate left (1 byte)
    rotated_word = word[1:] + word[:1]
    
    # Step 2: SubBytes - sử dụng bảng S-box
    sub_word = []
    for byte in rotated_word:
        row = int(byte[0], 16)
        col = int(byte[1], 16)
        sub_word.append(s_box[row][col])

    # Step 3: XOR với Rcon cho vòng hiện tại
    rcon_word = rcon[round_num]
    g_word = []
    for i in range(4):
        g_word.append(gf8_plus(sub_word[i], rcon_word[i]))
    
    return g_word

# Sinh khóa cho 10 vòng
def key_expansion(key_words):
    expanded_keys = key_words[:]
    
    for round_num in range(10):
        # Lấy từ cuối cùng của khóa trước
        last_word = expanded_keys[-1]
        
        # Sinh từ mới bằng hàm g và XOR với từ đầu tiên của khóa trước
        new_word = g(last_word, round_num)
        
        # XOR với từ đầu tiên của khóa trước
        for i in range(4):
            new_word[i] = gf8_plus(new_word[i], expanded_keys[-4][i])
        
        expanded_keys.append(new_word)
        
        # Sinh các từ tiếp theo bằng cách XOR với các từ khóa trước
        
        for _ in range(3):
            last_word = expanded_keys[-1]
            prev_word = expanded_keys[-4]
            new_word = [gf8_plus(last_word[i], prev_word[i]) for i in range(4)]
            expanded_keys.append(new_word)
    
    grouped_key = []
    for i in range(0, len(expanded_keys), 4):
        new_group = []
        for key in expanded_keys[i:i+4]:
            new_group.append(key)
        new_group = transpose_matrix(new_group)
        grouped_key.append(new_group)

    return grouped_key


    
    
def generate_key_schedule(plain_text_key):
    # Khóa nhập vào là plain text
    # plain_text_key = "Thats my Kung Fu"  # Đảm bảo khóa này dài 16 ký tự (128-bit)

    # Chuyển đổi thành key schedule (danh sách các từ 32-bit)
    key_schedule = text_to_key_schedule(plain_text_key)
    for i, key in enumerate(key_schedule, 1):
        print(f"Key origin {i}: {key}")


    # Sinh các khóa
    expanded_keys = key_expansion(key_schedule)
    # Hiển thị kết quả
    for i, key in enumerate(expanded_keys):
        print(f"Key expansion {i}: {key}")
        
    return expanded_keys
