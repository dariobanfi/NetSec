#!/usr/bin/env python

from pyDes import des
from pyDes import CBC
import binascii

# binascii.hexlify(bytes) will give you a hex representation of bytes
# binascii.unhexlify(hexstring) will give you a byte representation of hexstring
# we use 5edcc504 as initialisation vector

# This is how you compute 2DES
# You also see how we have used the pyDES library to create our ciphertext:
# Block mode is CBC, without any padding.
def twodes(plain, keyOne, keyTwo):
    cipherOne = des(binascii.unhexlify(keyOne), CBC, "5edcc504", pad=None)
    cipherTwo = des(binascii.unhexlify(keyTwo), CBC, "5edcc504", pad=None)
    return cipherTwo.encrypt(cipherOne.encrypt(plain))


cipherOne = des(binascii.unhexlify('0000000000000555'), CBC, "5edcc504", pad=None)

print binascii.hexlify(cipherOne.encrypt('ciaociao'))