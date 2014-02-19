#!/bin/python

'''

Library containg crypto and general functions used both
by the client and the server_certificate

'''

from Crypto.Util.asn1 import DerSequence
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
from Crypto.Random import _UserFriendlyRNG as Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from M2Crypto import X509 as m2x509
from OpenSSL import crypto as ocrypto
from binascii import a2b_base64, hexlify, unhexlify
from base64 import b64decode, b64encode
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 

def sha1(message):

    '''
    Param message: string
    Returns a hash of the given message with sha1 algorithm
    '''
    
    sha1payload = SHA.new()
    sha1payload.update(message)
    return sha1payload.hexdigest()

def encrypt_rsa(public_key, message):

    '''
    param: public_key Crypto.PublicKey.RSA
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''

    rsakey = PKCS1_OAEP.new(public_key)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')


def decrypt_rsa(private_key, message):

    '''
    param: private_key Crypto.PublicKey.RSA
    param: message String to be decrypted
    return decrypted string
    '''

    rsakey = PKCS1_OAEP.new(private_key) 
    decrypted = rsakey.decrypt(b64decode(message))

    return decrypted

def sign_rsa(private_key, msg):

    '''
    param: private_key
    param: msg to be signed
    return: base64 encoded signature
    '''

    signer = PKCS1_v1_5.new(private_key) 
    digest = SHA256.new()
    digest.update(msg) 
    sign = signer.sign(digest)

    return b64encode(sign)


def verify_signature(public_key, signature, msg):
    '''
    Verifies if the signature is valid with the public key
    param: public_key
    param: signature String signature to be verified
    return: Boolean. True if the signature is valid; False otherwise. 
    '''

    signer = PKCS1_v1_5.new(public_key) 
    digest = SHA256.new()
    digest.update(msg) 
    if signer.verify(digest, b64decode(signature)):
        return True
    return False




def __read_pubkey_from_der(blob):

    '''

    This will read an RSA public key from a DER binary blob.

    Arguments:
    blob -- binary string representing a DER file (read from file)

    Returns:
    RSA public key for use with pyCrypto (Crypto.PublicKey.RSA)

    '''
    cert = DerSequence()
    cert.decode(blob)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]
    return RSA.importKey(subjectPublicKeyInfo)
    


def read_pubkey_from_pem(pemstring):

    '''
    This will read an RSA public key from a PEM string.
    Idea:
     * Convert PEM to DER using binascii
     * Call __read_pubkey_from_der

    Arguments:
    pemstring -- String representing a certificate in PEM format

    Returns:
    RSA public key for use with pyCrypto (Crypto.PublicKey.RSA)
    '''

    lines = pemstring.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    return __read_pubkey_from_der(der)



def __read_privkey_from_der(blob):

    '''
    This will read an RSA private key from a DER binary blob.

    Arguments:
    blob -- binary string representing a private key in DER format (read from file)

    Returns:
    RSA private key for use with pyCrypto (Crypto.PublicKey.RSA)
    '''

    return RSA.importKey(blob)



def read_privkey_from_pem(pemstring):

    '''
    This will read an RSA private key from a PEM string.

    Arguments:
    pemstring -- String representing a private key in PEM format

    Returns:
    RSA private key for use with pyCrypto (Crypto.PublicKey.RSA)
    '''

    lines = pemstring.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    return __read_privkey_from_der(der)



def generate_random(bytes):

    '''
    Generate a random number.

    Returns:
    random number -- byte array
    '''

    return Random.get_random_bytes(bytes)

def generate_key(bytes=16):
    return generate_random(bytes)




def generate_nonce(bytes=28):

    '''
    Generate random nonce.
    Returns:
    nonce -- byte array
    '''

    return generate_random(bytes)




def read_subject(pem):

    '''
    Read subject of a X.509 certificate.

    Arguments:
    pem -- String representing a certificate in PEM format

    Returns:
    String of subject components
    '''

    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_subject()


def read_issuer(pem):

    '''
    Read issuer of a X.509 certificate.

    Arguments:
    pem -- String representing a certificate in PEM format

    Returns:
    Tuple of issuer components
    '''

    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_issuer()



def read_notafter(pem):

    '''
    Read notafter of a X.509 certificate.

    Arguments:
    pem -- String representing a certificate in PEM format

    Returns:
    String representing notafter
    '''
    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_notAfter()



def verify_certificate(issuer_cert, cert):

    '''
    Verifies the signature of a certificate.
    WARNING: Does not validate anything except the signature.

    Arguments:
    issuer_cert -- issuer certificate, in PEM, String.
    cert -- certificate whose signature is to be verified. In PEM, String.
    '''

    issuer_pubkey = m2x509.load_cert_string(issuer_cert, m2x509.FORMAT_PEM).get_pubkey()
    return m2x509.load_cert_string(cert, m2x509.FORMAT_PEM).verify(issuer_pubkey)




def create_hmac(secret, data):

    '''
    Create a HMAC from a key and data.

    Arguments:
    secret -- HMAC key, binary array
    data -- data to be hashed, binary array

    Returns:
    HMAC value as hex string
    '''

    h = HMAC.new(secret, 'sha')
    h.update(data)
    return h.hexdigest()



'''
Lambda function to do padding and unpadding of a message in order to make it
usable for CBC modes
'''

pad_16 = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16) 
unpad_16 = lambda s : s[0:-ord(s[-1])]

def encrypt_aes_cbc_128( key, msg ):
    '''
    Returns the encrypted value as hex of the message
    '''
    msg = pad_16(msg)
    key = key.decode('hex')
    iv = Random.new().read(AES.block_size);
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return ( iv + cipher.encrypt( msg ) ).encode("hex")

def decrypt_aes_cbc_128( key, msg ):
    '''
    Decrypts through the given key
    '''
    msg = msg.decode("hex")
    key = key.decode('hex')

    iv = msg[:16]
    msg= msg[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad_16(cipher.decrypt( msg))


if __name__== '__main__' :
    k = '140b41b22a29beb4061bda66b6747e14'
    

    print encrypt_aes_cbc_128(k,'ciao')

