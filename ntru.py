import random
from fraction import Fraction
from polynomial import Polynomial

#===================================
#Parameters
n = 43
p = 3
q = 32
df = 4
dg = 2
d = 3

#poly = x^N -1
poly = Polynomial([-1] + [0] * (n-1) + [1]) 

#===================================

#Get a random polynomial in L(d1,d2)
def randpoly(d1, d2, n=n):

    def shuffle(lst):
        random.shuffle(lst)
        return lst

    coefs = shuffle(list(range(n)))[:d1 + d2]
    pos = shuffle(coefs)[:d1]
    poly = [0 for i in range(n)]
    
    for i in coefs:
        if i in pos:
            poly[i] = 1
        else:
            poly[i] = -1
    return Polynomial(poly)
    
#Gets a random (invertible) polynomial in L(d1,d2)
def randInvertPoly(d1, d2, n=n): 
    while True:
        try:
            f = randpoly(d1,d2,n=n)
            inv = f.inverse(poly)
            fp = inv % p
            fq = inv % q
            return f, fp, fq
        except ValueError:
            continue

#===================================

#Private key
f, fp, fq = randInvertPoly(df,df-1)
g = randpoly(dg,dg)

#Public key
h = (fq * g) % poly % q 

#Encryption
#Encrypted message E = p * phi * h + M mod q
def encrypt(message):
    phi = randpoly(d,d)
    return (Polynomial([p]) * phi * h + message) % poly % q

#Decryption
#a = centered lift of f * E mod q, M = centered lift of Fp * a mod p
def decrypt(message):
    a = ((f * message) % poly % q).centeredLift(q)
    return ((fp * a) % poly % p).centeredLift(p)

#===============================

#Utility functions

#Convert an ASCII message to binary, then interpret the binary as a polynomial that can be encrypted.
def textToPoly(text):
    binary = ''
    for c in text:
        binary += format(ord(c),'08b')
    poly = [0 for i in range(len(binary))]
    for b in range(len(binary)):
        poly[b] = int(binary[b])
    return Polynomial(poly)

#Interpret a 0,1 polynomial as binary, then convert ot ASCII text.
def polyToText(poly): 
    message = ''
    binary = 0b0
    for i in range(len(poly.coefs) + 1):
        if i > 0 and i % 8 == 0:
            message += chr(binary)
            binary = 0
        if i < len(poly.coefs):
            binary <<= 1
            binary += poly.coefs[i].num
    return message

def encryptText(text):
    return encrypt(textToPoly(text))

def decryptText(message):
    return polyToText(decrypt(message))


    
    
    
                


