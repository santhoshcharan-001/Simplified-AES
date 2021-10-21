"""
    
    Name : Murarishetty Santhosh Charan
    Roll No : 2019287

"""
# 149, 151, 1 -> p,q,e client inputs

# 661, 673, 13 -> p,q,e server inputs

# message : 0b1010101010101010

# secret key : 0b0100101011110101

Basic Requirements To Run this Assignment: Python 3.9.0

Instructions to run this project:
    -> Firstly, Run Server.py and enter public key parameters (p,q,e).
    -> And then, Run Client.py and enter the required fields like:
        -> Message
        -> Secret Key
        -> Public Key Parameters (p,q,e)

Files used in this assignment are: 
    -> Client.py
    -> Server.py

    -> Functions used in both the files are:

        Basic Functions related to math and socket functions:
            -> function gcd(a, b) - used to find greater common divisor of two integers.
            -> function egcd(a, b) - used to find Euclidean GCD of two integers.
            -> function modinv(a,m) - function to find modular inverse.
            -> function pow(a,b,m) - The two-argument form pow(x, y) is equivalent to using the power operator: x**y. If three arguments are provided, then x to the power y, modulo z is returned. It's computed more efficiently than using pow(x, y) % z.
            -> function socket.socket() - Create and return a new socket object
            -> function socket.gethostbyname() - Resolve a hostname to a string quad dotted IP address.
            -> function bind( (adrs, port) ) - Bind the socket to the address and port.
            -> function accept() - Return a client socket (with peer address information)
            -> And remaining functions related to socket are for sending and recieving data.
       
        Functions related to Modified AES:
            -> function mult(p1, p2) - To multiply two polynomials in GF(2^4)/x^4 + x + 1
            -> function intToVec(n) - To convert a 2-byte integer into a 4-element vector
            -> function vecToInt(m) - To convert a 4-element vector into 2-byte integer
            -> function addKey(s1, s2) - To add two keys in GF(2^4)
            -> function sub4NibList(sbox, s) - For Nibble substitution function
            -> function shiftRow(s) - Shift rows and inverse shift rows of state matrix (same)
            -> function keyExp(key) - Extracting all the round keys for the given secret key 
            -> function encrypt(ptext) - Encrypt plaintext with given key
            -> function decrypt(ctext) - Decrypt ciphertext with given key 
            -> function iMixCol(s) - Inverse mix columns transformation on state matrix
            -> function mixCol(s) - Mix columns transformation on state matrix
        
        Functions related to RSA:
            -> RSA is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.
            -> Actually, to implement this algorithm I have used a class to maintain variables and functions.
            -> And I have constructors to initialize the variables of the class and utilized functions to calculate public parameters and private parameters.
            -> Functions related to this are:
                -> RSA - this is a constructor to initialize values of p,q,e
                -> function calculate_phi(self) - this is to compute φ(n), where φ is the Euler's totient function.
                -> function calculate_d(self) - to calculate d by performing modinv(e,n1) where n1 is φ
                -> function encrypt(self,message) - Function to encrypt the given data.
                -> function decrypt(self,c) -  Function to decrypt the given data.
                -> function hashlib.md5(bytes(str(message),encoding="UTF-8")) - This hash function accepts sequence of bytes and returns 128 bit hash value, usually used to check data integrity but has security issues.
                -> function hexdigest() - Returns the encoded data in hexadecimal format.
    Client.py:
        -> This file is the client which joins a socket server and sends all the data to the server
        -> This files initially accepts p,q,e values and then calculates pair of public and private keys.
        -> And it also accepts the message and secret key using Modified AES algorithm.
        -> And then it request for the server public key and then it encrypts it.
        -> calculates a hash digest for the given message and encrypt it using rsa using
        client private key.
        -> And then, it also sends the values calculated to the server.

    Server.py:
        -> This file is the server which creates a socket server and receives the data from the client and verifies it.
        -> It initially accepts p,q,e values and then calculates pair of public and private keys.
        -> And it decrypts the secret key sent by the client using the RSA using server private key.
        -> And then, it also decrypts the message sent by the client using modified AES using the secret key and cipher text sent by the client.
        -> Then, hash the resulted plain text.
        -> Decrypt the client signature sent by the client using the client public key .
        -> And verify the hash of the plaintext and decrypted signature are same or not. If same, then signature is verified, if not, it is not verified.