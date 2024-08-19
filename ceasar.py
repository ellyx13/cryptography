import string
import enchant


# Function to check if a word is valid using WordNet
def is_valid_word(word):
    d = enchant.Dict("en_US")
    return d.check(word)

# Function to decrypt the ciphertext using a specific key
def decrypt_with_key(ciphertext, key):
    alphabet = string.ascii_uppercase
    plaintext = ""
    for char in ciphertext:
        # Find the index of the character in the alphabet
        index_char = alphabet.find(char)
        if char == " ":
            plain_char = " "
        elif index_char < key:
            plain_char = alphabet[(index_char + 26 - key) % 26] 
        else:
            plain_char = alphabet[(index_char - key) % 26] 
        plaintext += plain_char
    return plaintext

# Function to attempt decryption without knowing the key
def decrypt_without_key(ciphertext):
    # Split the ciphertext into words
    words = ciphertext.split()
    for key in range(1, 26):
        plaintext = ""
        # Assume the key is valid until proven otherwise
        is_valid_key = True
        for word in words:
            # Decrypt each word with the current key
            word_decrypted = decrypt_with_key(word, key)
            if not is_valid_word(word_decrypted):
                # If any word is invalid, this key is not correct
                is_valid_key = False
                break
            plaintext += word_decrypted + " "
        if is_valid_key:
            print('Valid key:', key)
            return plaintext
    print('No valid key found')
        
def decrypt(ciphertext, key):
    if key == 0:
        return decrypt_without_key(ciphertext)
    else:
        return decrypt_with_key(ciphertext, key)
        
# Function to encrypt the plaintext using a specific key
def encrypt(plaintext, key):
    alphabet = string.ascii_uppercase
    ciphertext = ""
    for char in plaintext:
        # Find the index of the character in the alphabet
        index_char = alphabet.find(char)
        if char == " ":
            cipher_char = " "
        else:
            cipher_char = string.ascii_uppercase[(index_char + key) % 26] 
        ciphertext += cipher_char
    return ciphertext


def main():
    while True:
        option = input("Would you like to encrypt or decrypt? (decrypt/encrypt/exit): ")
        if option == "exit":
            break
        elif option == "encrypt":
            plaintext = input("Enter the plaintext: ")
            key = int(input("Enter the key: "))
            result = encrypt(plaintext, key)
        elif option == "decrypt":
            ciphertext = input("Enter the ciphertext: ")
            key = int(input("Enter the key, if you don't have, enter 0: "))
            result = decrypt(ciphertext, key)
        else:
            print("Invalid option. Please enter 'encrypt', 'decrypt', 'exit'.")
            continue

        print("Result: ", result)
        
main()