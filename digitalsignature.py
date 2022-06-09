import hashlib
import sage
from past.builtins import raw_input


def eucalg(a, b):
    # make a the bigger one and b the lesser one
    swapped = False
    if a < b:
        a, b = b, a
        swapped = True
    # ca and cb store current a and b in form of
    # coefficients with initial a and b
    # a' = ca[0] * a + ca[1] * b
    # b' = cb[0] * a + cb[1] * b
    ca = (1, 0)
    cb = (0, 1)
    while b != 0:
        # k denotes how many times number b
        # can be substracted from a
        k = a // b
        # a  <- b
        # b  <- a - b * k
        # ca <- cb
        # cb <- (ca[0] - k * cb[0], ca[1] - k * cb[1])
        a, b, ca, cb = b, a - b * k, cb, (ca[0] - k * cb[0], ca[1] - k * cb[1])
    if swapped:
        return (ca[1], ca[0])
    else:
        return ca


def keysgen(p, q):
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    e = 35537
    d = eucalg(e, lambda_n)[0]
    if d < 0: d += lambda_n
    # both private and public key must have n stored with them
    print("Private key:", d, "Public key:", e, "n:", n)
    return d, e, n


# Source Side #

# write a function named sourceXOR that takes private key of the source and public key of the destination
# and returns the XOR of the two keys
def XOR(privateKey, publicKey):
    return sage.xor(privateKey, publicKey)


# write a function named hashFunc that computes and returns the hash value of the source node
def hashFunc(plaintext):
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()


# write a function named encryptSource that encrypts and returns the hash value,
# which is the signature (S) of the source. Note that the encryption is symmetric key
def encrypt(pk,n,  plaintext):
    # Unpack the key into it's components
    key = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher


def conc(X, Y):
    return X + "EDP" + Y


# write a function named sessionKeyGen that generate a large integer denoting
# the session key. The key K_s must have at least 10 digits
def sessionKeyGen():
    return sage.random_integer(10)


def signID(ID, S, K_s, KU_dst):
    return conc(encrypt(K_s, conc(ID, S)), encrypt(KU_dst, K_s))


# write a function named send that takes the return value of signID and dest_IP as input and sends the signed value
# to the destination, if send process is successful it will return true, otherwise it will return false
def send(signedValue, dest_IP):
    return sage.send(signedValue, dest_IP)


# Destination Side #


def decrypt(pk,n, ciphertext):
    # Unpack the key into its components
    key = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)


if __name__ == '__main__':
    print("Implementation of Secure Authentication Protocol")
    p = int(raw_input("Enter a prime number (17, 19, 23, etc): "))
    q = int(raw_input("Enter another prime number (Not one you entered above): "))
    print("Generating your public/private keypairs now . . .")
    public, private,n = keysgen(p, q)
    print("Your public key is ", public, " and your private key is ", private, "and n is ", n)




