import struct
import socket
from Utils.stuff import generate_password, sign_message, verify_signature, encrypt_message, decrypt_message


SIZE_OF_CODE = 6
SIZE_OF_PASSWORD = 10

class Client:
    id : int
    code : str
    def __init__(self, id, code):
        self.id = id
        self.code = code

    def GetCode(self) -> str:
        return self.code

class Register:
    Clients : dict
    
    def __init__(self):
        self.Clients = {}

    def GenNewClient(self):
        self.Clients[generate_password(SIZE_OF_PASSWORD)] = Client(len(self.Clients), Utils.generate_password(SIZE_OF_CODE))
    
    def GetClientCode(self, password : str):
        return self.Clients[password].GetCode()
    
    def VerifyClient(self, password : str) -> bool:
        return password in self.Clients

class Message:
    id : int
    body : str
    EncryptedContent : str
    def __init__(self, content : str) -> None:
        self.EncryptedContent = content
    


class Manager:
    def MakeNewClient():
        pass
    def GetMessage():
        pass
    def SendMessage():
        pass

def SendBySecureChannel():
    pass


def main():
    print(generate_password(12))
    message = "hello"
    s, i, enc = encrypt_message(message, "lol")
    print(s.hex())
    print(i.hex())
    print(enc.hex())
    dec = decrypt_message(s, i, enc, "lol")
    print(dec)

if __name__ == "__main__":
    main()