import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

def main():
    st.text(" By.Rehand Naifisurya H (227006117)")
    st.title("Advanced Encryption Standard")
    st.header("AES Encryption")

    key_input = st.selectbox("Masukkan Panjang Key (dalam byte):", [16, 24 , 32 ])
    st.write("---")
    st.text("""
            
            Contoh yang 16 byte: “HELLO, WORLD!HELLO, WORLD!”, Negara Indonesia, Bhineka Tunggal Ika
            Contoh yang 24 byte : “123456789012345678901234”, “HELLO, WORLD!HELLO, WORLD!” 
            Contoh yang 32 byte : 1234567891234567891234556789abcd """)
    key_bytes = st.text_input("Masukkan Kunci", "                ")  
    key= key_bytes.encode("utf-8")
    plaintext = st.text_input("Masukkan Plaintext", " ")  
    plaintext_bytes = plaintext.encode("utf-8")

    ciphertext = encrypt(plaintext_bytes, key)
    decrypted_text = decrypt(ciphertext, key)
    


    if st.button("Enkripsikan"):
        st.write(f"Plaintext: {plaintext_bytes}")
        st.write("Ciphertext:", ciphertext.hex())
        st.write(f"Key: {key_bytes}")

    
    if st.checkbox("Tampilkan Proses Dekripsi"):  
        st.write("---")
        st.header("AES Decryption")
        encrypted_text = st.text_input("Masukkan Ciphertext:", value = ciphertext.hex())
        key_bytes2 = st.text_input("Masukan key:", value = key_bytes)
        if key_bytes != key_bytes2 :
            st.write("Key Salah")
        elif key_bytes == key_bytes2 :

            if st.button("Dekripsikan"):
                st.write(f"Ciphertext: {encrypted_text}")
                st.write("Decrypted text:", decrypted_text.decode("utf-8"))   

if __name__ == "__main__":
    main()
