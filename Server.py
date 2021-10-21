"""
    Name : Murarishetty Santhosh Charan
    Roll No : 2019287
"""
# making required imports
import socket
import hashlib

print("Murarishetty Santhosh Charan, 2019287")

# Function to calculate gcd of two numbers
def gcd(a, b):
	while b:
		a, b = b, a%b
	return a

# function to find extended gcd
def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

# function to find modular inverse
def modinv(a,m):
	g,x,y = egcd(a,m)
	if g != 1:
		return None
	else:
		return x%m
# class for implementing RSA.
# Class to access and use the variables and functions of RSA Algorithm 
class RSA:
    p=q=1
    # Euler's totient φ(n)
    n1=1
    n=1
    # Choose 1 < e < φ(n), which is coprime to φ(n)
    # Public Key Exponent
    e=1
    # Private key exponent d
    d=1

    # Constructor of the class to initialize the values
    def __init__(self,p,q,e):
        self.p=p
        self.q=q
        self.e=e
        # compute n = pq
        self.n=p*q

    # compute φ(n), where φ is the Euler's totient function
    def calculate_phi(self):

        self.n1=(self.p-1)*(self.q-1)
    
    def calculate_e(self):

        r = 5 # For efficiency 2 < e < 100
        while True:
            if gcd(r, self.n1) == 1:
                    break
            else:
                r += 1
        self.e = r

    # function to calculate d
    def calculate_d(self):
        self.d = modinv(self.e, self.n1)
    
    # Function to encrypt 
    def encrypt(self,message):

        return pow(message,self.e,self.n)

    # Function to decrypt 
    def decrypt(self,c):

        return pow(c,self.d,self.n)

print("Enter the value of p:",end=" ")
p = int(input())
print("Enter the value of q:",end=" ")
q = int(input())
print("Enter the value of e:",end=" ")
e = int(input())
# 661, 673, 13
main = RSA(p,q,13)


main.calculate_phi()

main.calculate_e()

main.calculate_d()

public_key ="take " + str(main.e) + " " + str(main.n)

# Implementation of Modified AES

# S-Box
sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]
 
# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
w = [None] * 6

# Functions related to Modified AES(mentioned in the README.txt)

# Function to multiply two polynomials in GF(2^4)/x^4 + x + 1
def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111
 
def intToVec(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
 
def vecToInt(m):
    """Convert a 4-element vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def addKey(s1, s2):
    """Add two keys in GF(2^4)"""  
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]
     
def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]
 
def keyExp(key):
    """Generate the three round keys"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
 
    Rcon1, Rcon2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]
 
def encrypt(ptext):
    print()
    print("Cipher text intermediate computation process:")
    """Encrypt plaintext block"""
    def mixCol(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]  
    print()  
    print("After Pre-round transformation:")
    print()
    print("Round key K0:",w[0]+w[1])
    print()
    state = intToVec(((w[0] << 8) + w[1]) ^ ptext)
    sub = sub4NibList(sBox, state)
    print("After Round 1 Substitute nibbles: ",sub)
    print()
    shif = shiftRow(sub)
    print("After Round 1 Shift rows: ",shif)
    print()
    state = mixCol(shif)
    print("After Round 1 Mix columns: ",state)
    print()
    state = addKey(intToVec((w[2] << 8) + w[3]), state)
    print("After Round 1 Add round key: ",state)
    print()
    sub = sub4NibList(sBox, state)
    print("Round key K1:",w[2]+w[3])
    print()
    print("After Round 2 Substitute nibbles: ",sub)
    print()
    state = shiftRow(sub)
    print("After Round 2 Shift rows: ",state)
    print()
    key = addKey(intToVec((w[4] << 8) + w[5]), state)
    print("After Round 2 Add round key: ",key)
    print()
    print("Round Key K2: ",w[4]+w[5])
    print()
    return vecToInt(key)
     
def decrypt(ctext):
    """Decrypt ciphertext block"""
    def iMixCol(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
    print("Decryption Intermediate process: ")
    print()
    print("After Pre-round transformation: ")
    print()
    print("Round Key K2: ",w[4]+w[5])
    print()
    state = intToVec(((w[4] << 8) + w[5]) ^ ctext)
    shif = shiftRow(state)
    print("After Round 1 InvShift rows: ",shif)
    print()
    state = sub4NibList(sBoxI, shif)
    print("After Round 1 InvSubstitute nibbles: ",state)
    print()
    key = addKey(intToVec((w[2] << 8) + w[3]), state)
    print("After Round 1 InvAdd round key:",key)
    print()
    print("Round key K1:",w[2]+w[3])
    print()
    state = iMixCol(key)
    print("After Round 1 InvMix columns: ",state)
    print()
    shif = shiftRow(state)
    print("After Round 2 InvShift rows: ",shif)
    print()
    state = sub4NibList(sBoxI,shif)
    print("After Round 2 InvSubstitute nibbles: ",state)
    print()
    key = addKey(intToVec((w[0] << 8) + w[1]), state)
    print("After Round 2 Add round key: ",key)
    print()
    return vecToInt(key)
# list to store the requests or msgs sent by the client
li = []


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    print()
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if data=="stop":
            break
        if data:
            # storing the messages sent by the client.
            li.append(str(data))
            # if the client requests the public key, we are sending the server public key.
            if str(data).strip()=="request":
                conn.send(public_key.encode())

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
    # print(li)
    # getting the encrpted secret key
    encrpted_secret_key=li[-3]
    # decrypting the secret key
    secret_key=main.decrypt(int(encrpted_secret_key))
    # key expansion
    keyExp(secret_key)
    print("Decrypted Secret Key",secret_key)
    print()
    t=int(li[1]) # CipherText
    message = decrypt(t)
    print("Decrypted Plaintext ",message)
    print()
    # This hash function accepts sequence of bytes and returns 128 bit hash value
    result = hashlib.md5(bytes(str(message),encoding="UTF-8"))
    # getting client signature
    client_signature = list(li[-1].split())
    # calculating hex digest 
    digest = result.hexdigest()
    # getting public_key of the client
    temp_list=list(li[-2].strip().split())
    a,b=int(temp_list[0]),int(temp_list[1])
    print("Message Digest: ",digest)
    print()
    # decrypting the client_signature 
    new_list= []
    for ele in client_signature:
        t=pow(int(ele),a,b)
        # checking whether it is int or string as i haved stored the ascii values for the characters and digits for the numbers.
        if len(str(t))==1:
            new_list.append(str(t))
        else:
            new_list.append(chr(t))
    check = "".join([str(ele) for ele in new_list])
    # checking whether the hashes are equal or not
    if check == digest:
        # Verified
        print("Client Signature Verified")
        print()
    else:
        # not verified
        print("Client Signature Not Verified")
        print()
