## Author: Elif Duygu PETENKAYA
## CE 340 - Cryptography and Network Security by Assoc. Prof. Suleyman Kondakci
## Project 3 - Implementation of Secure Authentication Protocol

import hashlib
import random as rand
from operator import xor

from urllib3.connectionpool import xrange


########## helper functions ##########
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, r):
    for i in range(r):
        if (e * i) % r == 1:
            return i


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in xrange(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def conc(X, Y):
    return X, "EDP", Y


###################### Source Side ######################

# sessionKeyGen that generate a large integer denoting the session key. The key K_s must have at least 10 digits and
# has n value of the product of the two prime numbers p and q
def sessionKeyGen(n):
    return rand.randrange(10 ** 10, 10 ** 11), n


def XOR(privateKey, publicKey):
    return xor(privateKey[0], publicKey[0])


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
        # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = rand.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = rand.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def hashFunc(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# write a function named encryptSource that encrypts and returns the hash value,
# which is the signature (S) of the source. Note that the encryption is symmetric key
def encrypt(plaintext, pub):
    key, n = pub
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    for char in (plaintext):
        cipher = [(ord(ch) ** key) % n for ch in char]
    # Return the array of bytes
    return cipher


# Z=signID(conc [E(conc(ID,S),KS)), E(KS, KUDST)]).
def signID(idText, S, KS, dstPublic):
    sessionKeyEnc = encrypt(conc(idText, S), KS)
    encrypted = encrypt(KS, dstPublic)

    Z = conc(sessionKeyEnc, encrypted)
    return Z


###################### Destination Side ######################

def decrypt(ciphertext, priv):
    key, n = priv
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((int(char) ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)


if __name__ == '__main__':
    print("Implementation of Secure Authentication Protocol by EDP")

    p = int(input("Enter a prime number (17, 19, 23, etc): "))
    q = int(input("Enter another prime number (Not one you entered above): "))

    print("Generating your public/private keypairs now . . .")

    srcPublic, srcPrivate = generate_keypair(p, q)
    print("Source public key is ", srcPublic, " and Source private key is ", srcPrivate)

    dstPublic, dstPrivate = generate_keypair(p, q)
    print("Destination public key is ", dstPublic, " and Destination private key is ", dstPrivate)

    print("Encrypting your message now . . .")
    idText = ""
    with open('ID.txt', 'r') as f:
        for line in f:
            idText += line.strip() + "/EDP/"
    print("ID is: ", idText)

    kH = XOR(srcPrivate, dstPublic), srcPublic[1]
    print("Kh for source is: ", kH)

    hashedText = hashFunc(idText)
    print("Hashed ID is: ", hashedText)

    encryptedHashedText = encrypt(hashedText, kH)
    encryptedHashedTextStr = " ".join(str(encryptedHashedText))
    S = conc(idText, encryptedHashedTextStr)

    print("Hashed and encrypted ID is: ", S)

    print("Session is generating now... Please wait for the session key to be generated.\n")
    KS = sessionKeyGen(dstPublic[1])
    print("Session key is: ", KS)

    print("Signing now... Please wait for the signature to be generated.\n")

    sessionKeyEnc = encrypt(conc(idText, S), KS)
    encrypted = encrypt(KS, dstPublic)

    print(sessionKeyEnc)
    print(encrypted)
    Z = conc(sessionKeyEnc, encrypted)
    print(Z)
    print("Signature is: ", str(Z))
