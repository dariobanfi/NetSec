#!/bin/python

import socket
import argparse
import utils 
import binascii
import datetime


def main():


    # Parsing the arguments through argparse module
    parser = argparse.ArgumentParser(description='Launch the miniSSL Server')
    parser.add_argument('address', help='Address of the server')
    parser.add_argument('port', help='Number of the port the server is listening on', type=int)
    parser.add_argument('clientcert', help='Name of the file containing the client certificate')
    parser.add_argument('clientkey', help='Name of the file containing the client key')
    args = parser.parse_args()

    try:

        # The SSLObject initiates the handshake procedure
        connection = SSLConnection(args.address, args.port, args.clientcert, args.clientkey)
        connection.client_init()

        # Once handshake has been done, we use miniGet (passing the SSLConnection object)
        miniget = miniGet(connection)
        payload = miniget.get()



        print 'Received:\t' + payload
        print 'Sha1Sum:\t' + utils.sha1(payload)

        f = open('received_file.txt', 'w')
        f.write(payload)
        f.close()

        connection.close()

    except Exception, e:
        print e
        return 



class miniGet:

    '''
    Abstraction of miniget protocol.
    The client simply sends a GET filename request, and the server
    responds with its content encrypted and hmaced
    '''

    def __init__(self, sslconnection):
        if not sslconnection.handshake_done:
            raise Exception('SSL Connection did not succeed')
        self.sslconnection = sslconnection

    def decrypt(self, message):
        '''
        We first decrypt with aes cbc 128 function and then we verify if the
        mac is correct or the message has been forged
        '''
        decrypted_message = utils.decrypt_aes_cbc_128(self.sslconnection.key_1, message)
        message = decrypted_message[32:]
        mac = decrypted_message[:32]

        if utils.create_hmac(self.sslconnection.key_2, message)!=mac:
            raise Exception('A message modification has been detected!')

        return message

        

    def get(self):

        '''
        Getting the file payload.txt (there was no file arg in the specification
            so I left it like this)
        '''

        message = 'GET' + '|' + 'payload.txt'

        self.sslconnection.server_connection.send(message)

        received_file = ''
        while 1:
            data = self.sslconnection.server_connection.recv(1024)
            if not len(data): break
            received_file += data

        return self.decrypt(received_file)

class SSLConnection:

    '''
    Abstraction of SSL handshake procedure, once finished both client and 
    server share the couple of keys used for encryption and verification
    '''

    # List of the trusted root certs
    root_certificates = ['minissl-ca.pem']

    def __init__(self, address, port,
        client_certificate, client_private_key):

        # Connection variables
        self.server_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_connection.connect((address, port))
        self.address = address
        self.port = port
        self.handshake_done = False

        # Client variables
        self.client_certificate = client_certificate
        with open (client_private_key, 'r') as client_pkey:
            self.client_private_key = utils.read_privkey_from_pem(client_pkey.read())

        self.cipher = 'AES-CBC-128-HMAC-SHA1'
        self.client_nonce = None

        # Server variables (setting them to None is useless, but it's just
        # to remember which vars the object stores)
        self.server_certificate = None
        self.server_nonce = None
        self.server_public_key = None
        self.server_requires_authentication = False
        
        # Couple of keys used for encryption/decryption and HMAC    
        self.key_1 = None
        self.key_2 = None

        # We store the message we sent
        self.clientinit = None
        self.serverinit = None

    def generate_client_nonce(self):
        self.client_nonce = binascii.hexlify(utils.generate_nonce())

    def close(self):
        self.server_connection.close()

    def client_init(self):

        # Sending message with message_type, client nonce and chosen  cipher, with fields separated
        # by the carachter '|'

        message_type = 'ClientInit'
        self.generate_client_nonce()
        self.clientinit = message_type + '|' + self.client_nonce + '|' + self.cipher


        self.server_connection.send(self.clientinit)




        # ---------------------------------------------------------------------------------------------------




        # Receiving the first response from the server
        self.serverinit = self.server_connection.recv(8192) # Should be enough to receive all the data

        print '-------------------------------\n'
        print self.serverinit
        print '\n-------------------------------'


        response_splitted = self.serverinit.split('|')

        # We check if it is the expected message type and if the server
        # acknowledged our cipher

        if not response_splitted[0] == 'ServerInit' or not response_splitted[2] == self.cipher:
            print 'Invalid response type, %s' % self.serverinit
            self.server_connection.close()
            return

        self.server_certificate = response_splitted[3]
        if not self.certificate_is_valid(self.server_certificate):
            print 'Invalid certificate'
            self.server_connection.close()
            raise Exception('Invalid server certificate')

        # Checking if the server requires client authentication
        try:
            if response_splitted[4] == 'CertReq':
                self.server_requires_authentication = True
        except IndexError:
            pass

        self.server_nonce = response_splitted[1]
        pre_master_secret = utils.generate_key(bytes=48)

        # Generating the 2 keys (for encryption and mac)
        key_1_payload = binascii.unhexlify(self.client_nonce + self.server_nonce + '00000000')
        key_2_payload = binascii.unhexlify(self.client_nonce + self.server_nonce + '11111111')
        self.key_1 = utils.create_hmac(pre_master_secret, key_1_payload)
        self.key_2 = utils.create_hmac(pre_master_secret, key_2_payload)




        # The control message is like this:
        # ClientInit| nc|AES-CBC-128-HMAC-SHA1|ServerInit|ns|Certs [|CertReq])
        # We remove the cipher from the server msg since it's already in the client one

        message_control = utils.create_hmac(
            self.key_2,
            self.clientinit + self.serverinit.replace( '|' + self.cipher, '')
            )

        # Sending to the server the PMS, mac of messages and optional client certificate

        server_public_key = utils.read_pubkey_from_pem(self.server_certificate)
        rsa_encrypted_pms = utils.encrypt_rsa(server_public_key, pre_master_secret)

        message_for_server = 'ClientKex' + '|' + rsa_encrypted_pms + '|' + message_control

        signed_nonce = ''

        if self.server_requires_authentication:

            with open (self.client_certificate, 'r') as client_certificate:
                client_certificate_data=client_certificate.read()
            message_for_server = message_for_server + '|' + client_certificate_data

            # I send the signed server nonce to the server so he can verify it

            signed_nonce = utils.sign_rsa(self.client_private_key, self.server_nonce + rsa_encrypted_pms)

            message_for_server = message_for_server + '|' + signed_nonce


        self.server_connection.send(message_for_server)






        # -------------------------------------------------------------------------------------------------------------------





        # Receiving last message of handshake

        server_response = self.server_connection.recv(8192)

        print '-------------------------------\n'
        print server_response
        print '\n-------------------------------'

        # If the message checksum send from the server is equals to ours,
        # the handshake is finally terminated!

        if signed_nonce!='':
            expected_verification_messages = utils.create_hmac(self.key_2, message_for_server.replace('|' + signed_nonce, ''))
        else:
            expected_verification_messages = utils.create_hmac(self.key_2, message_for_server)

        if server_response == expected_verification_messages:
            
            self.handshake_done = True

        else:

            raise Exception('Detected some problems with verification of messages')




    def certificate_is_valid(self, pemstring):

        # We check if it is the expected name

        is_expected_name = utils.read_subject(pemstring).commonName == 'minissl-SERVER'

        # Check if it's not expired

        cert_date = utils.read_notafter(pemstring)
        cert_date = datetime.datetime.strptime(cert_date, '%Y%m%d%H%M%SZ')
        is_not_expired = datetime.datetime.now() < cert_date

        # Check if it's issued by one of our root certificates
        # (in the list we have only one)

        is_valid = 0
        for rootcert in self.root_certificates:
            with open (rootcert, 'r') as ca_certificate:
                ca_certificate_data=ca_certificate.read()
                is_valid = utils.verify_certificate(ca_certificate_data, pemstring)
                if is_valid:break

        return is_expected_name and is_not_expired and is_valid



main()