#!/usr/bin/env python

'''

The following program use the meet-in-the-middle attack
to recover two key values used to encrypt a message with
a 2DES algorithm

First, it creates a hastable with all the possible keys and
the encryption of the given plaintext, then it decrypts the 
ciphertext with all the possible combinations of keys and
looks up on the the hashtable if the ciphertexts match.
If yes, we found the right password combination, and we 
print them to stdout.

'''

from twodes import *
import binascii
import sys

__author__      = "Banfi Dario"

inizialization_vector = '5edcc504'

plaintext = sys.argv[1]
ciphertext = sys.argv[2]
effKeyLength = sys.argv[3]



def generateTable(plaintext, effKeyLength):

	'''

	This function generates a hashtable (a python dictionary,
	useful to do quick lookups in time O(1))
	with as key, the encrypted plaintext and as value the key 
	used to encrypt the plaintext.
	It encrypts all the entries starting from key 0*n to key F*n,
	depending on the effKeyLength and returns the generate generateTable

	'''

	# Start and End of the loop, retreived from the esadecimal number -> int(n,16)
    start = int('0'*int(effKeyLength), 16)
    end = int('f'*int(effKeyLength), 16)

    enctable = {}

    # It loops through all the effective key combinations, appending leading zeros to
    # reach the desired 64bit key length with the c-like notation '%016x'

    for i in xrange(start, end + 1):
        key = '%016x' % i

        # Encrypting the plaintext with the key just computed
        byte_plaintext = des(binascii.unhexlify(key), CBC, inizialization_vector, pad=None).encrypt(plaintext)

        # Setting the ciphertext as key and the key as value of the table
        enctable[binascii.hexlify(byte_plaintext)] = key

    return enctable


def lookupInTable(enctable, ciphertext, effKeyLength):

	'''

	Decrypts the ciphertext with all the possible passwords
	and compares it with the table generated in the first step.
	If the match is positive, it prints the key couple

	'''

	# Same as the first function 

    start = int('0'*int(effKeyLength), 16)
    end = int('f'*int(effKeyLength), 16)

    for i in xrange(start, end + 1):
        key_2 = '%016x' % i

        # Decrypting the cipher with the computed key

        decrypted_value = binascii.hexlify(des(binascii.unhexlify(key_2), CBC, inizialization_vector, pad=None)
            .decrypt(binascii.unhexlify(ciphertext)))

        # This like checks wheter the ciphertext we obtained by
        # decrypting the element is found in the hashtable and if
        # yes, we print it and we stop the execution
        #
        # the "key in hashtable.keys()" operation takes O(1) time
        
        if decrypted_value in enctable.keys():
            print "Key1:" + enctable[decrypted_value]
            print "Key2:" + key_2
            return

def main():
    enctable = generateTable(plaintext, effKeyLength)
    lookupInTable(enctable, ciphertext, effKeyLength)

main()
