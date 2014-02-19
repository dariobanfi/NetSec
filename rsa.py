#!/usr/bin/env python

import sys

#Compute all primes between 0 and max
#Input:
#max: maximum size of primes. Type: Integer
#Output:
#primes: ordered list of the primes between 1 and max
def computePrimes(max):

    ''' This function is made up with 2 cycles.
        The first one iterates 'num' from 2 to the max number given.
        The second one iterates j from 2 to the current position of num, trying to find
        number which divide without rest.
        In case they are found, the cycle stop, otherwise we have found a prime number'''

    primes = []
    for num in range(2,max):
        is_prime = True
        for j in range(2,num):
            if num%j == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)

    return primes

# Compute a public key
# Input:
# p, q: primes. Type: integer. Constraints: p, q < 300, p != q
# Output:
# (n, e): tupel of integers representing the public key
def computePubKey(p, q):

    ''' This function computes the pubkey by choosing the smallest possible prime number e wich is coprime with phi(pq)
        Once it is found the cycle breaks and the values n and e are returned, as public key '''

    assert (p < 300)
    assert (q < 300)
    assert (p != q)
    e = 0
    n = p*q
    primes = computePrimes(300)
    for num in primes:
        if gcd( computePhi(p, q), num ) == 1:
            e = num
            break
    return (n, e)
    
       
# e and phi(n) are input, both integers
# Compute a private key
# Input:
# e, phi(n): as in lecture. Type: integer.
# Output:
# d: private key. Type: integer
def computePrivKey(e, phi):

    ''' To compute the private key we use the Extended Euclidean Algorithm, by taking the
        bezout coefficent computed for the number e '''
    
    d,x = eea(e, phi)

    return d


# gcd() uses eea()
# Input:
# a, b: numbers to work on. Type: integer
# Output:
# gcd: the gcd. Type: integer
def gcd(a, b):

    ''' This gcd function simply uses the Extended Euclidean Algorithm implementation,
        and multiplies the coefficents with the terms a and b '''

    bezout = eea(a,b)
    return a*bezout[0]+b*bezout[1]


# Compute phi(n) if input is a product of two primes
# Input:
# p, q: primes. Type: integer
# Output:
# o: phi(n). Type: integer

# eea is the Extended Euclidean Algorithm
# Input:
# a, b: numbers to work on. Type: integer
# Output:
# (x, y): numbers for which ax + by = gcd(a,b) holds. Type: tupel of integers
def eea(a, b):

    ''' This is the implementation of Extended Euclidean Algorithm.
        The algorithm not only computes the gcd (wich will be in old_r variable),
        but also find the value of two numbers x and y (old_x and old_in the code)
        such that the identy xa+yb=gcd(a,b) is valid. '''
    
    x = 0
    old_x = 1
    y = 1
    old_y = 0
    r = b
    old_r = a
    while r != 0:
        q = old_r / r
        old_r, r = r, old_r % r
        old_x, x = x, old_x - q *x
        old_y, y = y, old_y - q *y

    return (old_x, old_y)

def computePhi(p, q):

    ''' This function computes the Euler's totient number by cycling from 1 to p*q and increasing
        the 'o' variable if x and p*q are coprime '''
    
    num = p*q
    x = 1
    o = 0
    while(x<=num):
        if gcd(x,num) == 1:
            o += 1
        x += 1
    return o


# Compute an encrypted message
# Input:
# m: the message. Type: integer. Constraint: m < n
# pubkey: public key. Type: tupel of integers (n, e)
# Output:
# ciphertext: encrypted message. Type: integer
def encrypt(m, pubkey):

    ''' This function encrypts the message with the givn pubkey
        What I'm doing is basically this operation : 
        (m**e) % n
        using the modular exponentiation method in order to 
        use less resources. '''

    (n,e) = pubkey
    assert(m<n)

    ciphertext = 1
    m = m%n
    while(e>0):
        ciphertext = ciphertext*m
        ciphertext = ciphertext%n
        e -= 1

    return ciphertext


# Decrypt an encrypted message
# Input:
# c: the ciphertext. Type: integer
# d: the private key. Type: integer
# n: the product of p and q. Type: integer
# Output:
# decryptedtext: the decrypted message. Type: integer
def decrypt(c, d, n):

    ''' It decrypts the message using  the same optimization of the encrypt function based on this expression:

        decryptedtext = c**d % n '''

    decryptedtext = 1
    c = c%n
    while(d>0):
        decryptedtext = decryptedtext*c
        decryptedtext = decryptedtext%n
        d -= 1

    return decryptedtext


# Use this if you want to test your program
# DO NOT CHANGE THE FORMAT OF COMMAND LINE CALL
def main():
    # we read from stdin
    # first prime number
    p1 = int(sys.argv[1])
    # second prime number
    p2 = int(sys.argv[2])
    # message to encode, given as an integer m < n = p1 * p2
    m = int(sys.argv[3])

    # DO NOT CHANGE THE OUTPUT FORMAT
    (n, e) = computePubKey(p1, p2)
    print "Pubkey:" + str(n) + "," + str(e)
    phi = computePhi(p1, p2)
    print "Phi:" + str(phi)
    d = computePrivKey(e, phi)
    print "PrivKey:" + str(d)
    c = encrypt(m, (n, e))
    print "m:" + str(m) + "->" + str(c)
    print "c:" + str(c) + "->" + str(decrypt(c, d, n))

main()