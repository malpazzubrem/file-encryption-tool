import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypting():
    salt = os.urandom(16) #generating salt
    key_generation = PBKDF2HMAC( #deriving key
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_200_000,
    )
    print("write down your file path")
    path = input()
    if not(os.path.exists(path)): #checking if file exists
        print("please input correct path")
        encrypting()
    print("write down password to your file")
    passwd = input() 
    nonce = secrets.token_bytes(12)
    key = key_generation.derive(passwd.encode())
    aes = AESCCM(key)

    with open(path,"rb") as f: #opening file and encrypting it
        file = f.read()
        encrypted_file = aes.encrypt(nonce,file,None)
    return encrypted_file,path,aes,nonce,salt

def new_file():
    print("write file name")
    name = input()
    
    with open(f"{name}.txt","w") as f:
        f.write(salt.hex()) #saving all salt nonce etc.
        f.write(nonce.hex()) 
        f.write(encrypted_file.hex())
    print("file created succesfully")



def decrypting():
    print("write file to decrypt")
    path = input()
    if not(os.path.exists(path)): #checking if file exists
        print("please input correct path")
        decrypting()
    print("write down password to your file")
    passwd = input()


    with open(path, "r", encoding="utf-8") as f: #opening file and encoding it
        data = f.read() 

    salt_hex       = data[:32] #getting salt nonce etc
    nonce_hex      = data[32:56]
    ciphertext_hex = data[56:]

    salt       = bytes.fromhex(salt_hex) #hex to bytes
    nonce      = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    key_generation1 = PBKDF2HMAC( #getting key
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
        
    key = key_generation1.derive(passwd.encode())
    aes = AESCCM(key)
    try:
        plainfile = aes.decrypt(nonce,ciphertext,None) #decrypting it
    except:
        print("wrong password")
        decrypting()
    print(plainfile)
    print("1)replace existing file")
    print("2)write a new file")
    ans = input()

    if ans == "1":
        with open(path,"w")as f:
            f.write(plainfile.decode()) #overwriting file
        print("file successfully replaced")

    elif ans == "2":
        print("write down name for your file")
        name = input()

        with open(f"{name}.txt","w")as f: #creating a new one
            f.write(plainfile.decode())
        print("file successfully created")
    else:
        print("please choose correct option")
        decrypting()

if __name__ == "__main__": #main menu
    print("1)encrypt file")
    print("2)decrypt file")
    ans = input()
    if ans == "1":
        encrypted_file,path,aes,nonce,salt = encrypting()
        print("1)create new file")
        print("2)replace file")
        ans = input()
        if ans == "1":
            new_file()
        elif ans == "2":
            with open(path,"w")as f:
                f.write(salt.hex())
                f.write(nonce.hex()) 
                f.write(encrypted_file.hex())
                print("file succesfully replaced")
    
    elif ans == "2":
        decrypting()
    else:
        pass
