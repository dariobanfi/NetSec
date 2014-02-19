#!/bin/python

import argparse
import thread
import socket
import binascii
import utils
import datetime


def main():

    # Parsing the args with argparse module
    parser = argparse.ArgumentParser(description='Launch the miniSSL Server')
    parser.add_argument('listen_port', help='Port number on which the server will be bound', type=int)
    parser.add_argument('servercert', help='Name of the file containing server certificate')
    parser.add_argument('serverprivatekey', help='Name of the file containing server private key')
    parser.add_argument('authentication', help='Type of authentication', choices=['SimpleAuth', 'ClientAuth'])
    parser.add_argument('payload', help='Name of the payload file')
    args = parser.parse_args()

    # Binding the server and starting a thread for every connection he receives
    HOST = ''
    PORT = 50000

    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind((HOST,PORT))
    serversock.listen(5)
    
    while 1:
        print 'Waiting for connections'
        clientsock, addr = serversock.accept()
        thread.start_new_thread(handle_client, (clientsock, addr, args))


def handle_client(clientsock, addr, args):

    '''
    This function handles client requests by trying to receive sslconnection
    requests, and starting miniGet server if the handshake is succesful
    '''

    client_connection = SSLServerConnection(clientsock, args)

    try:
        client_connection.receive_client_init()
    except Exception,e :
        print e

    if client_connection.handshake_done: # Succesful handshake
        try:
            minigetserver = miniGet(client_connection, args.payload)
            minigetserver.accept()
        except Exception, e:
            print e


    clientsock.close()

    print 'Closed the connection with %s' % repr(addr)

class miniGet():

    ''' 

    Miniget protocol, it accepts requests like 'GET filname'
    and send them back encrypted and hmaced

    '''

    def __init__(self, sslconnection, filename):
        if not sslconnection.handshake_done:
            raise Exception('SSL Connection did not succeed')
        self.sslconnection = sslconnection
        self.file = filename

    def accept(self):
        request =self.sslconnection.clientsock.recv(1024)
        request_splitted = request.split('|')
        if request_splitted[0] == 'GET':
            try:
                with open (self.file, 'r') as requested_file:
                    payload=requested_file.read()

                message = self.miniget_encryption(payload)
                self.sslconnection.clientsock.send(message)

                print 'Sent:\t' + payload
                print 'Sha1Sum\t:' + utils.sha1(payload)

            except IOError:
                self.clientsock.send('Invalid file request')

    def miniget_encryption(self, message):

        # Creating mac
        mac = utils.create_hmac(self.sslconnection.key_2, message)

        message =  mac + message

        # Encrypting with the encryption key
        return utils.encrypt_aes_cbc_128(self.sslconnection.key_1, message)

class SSLServerConnection:

    '''
    Abstraction of SSL handshake procedure, once finished both client and 
    server share the couple of keys used for encryption and verification
    '''

    # Root certificates and allowed ciphers by the server
    root_certificates = ['minissl-ca.pem']
    allowed_ciphers = ['AES-CBC-128-HMAC-SHA1']

    def __init__(self, clientsock, args):
        self.clientsock = clientsock
        self.handshake_done = False

        self.servercert = args.servercert
        self.serverprivatekey = args.serverprivatekey
        self.authentication = args.authentication
        self.payload = args.payload

        self.client_cipher = None
        self.client_nonce =  None
        self.client_certificate = None
        self.clientinit = None

        self.key_1 = None
        self.key_2 = None

    def receive_client_init(self):

        # Receiving data (hopefully first handshake message)
        self.clientinit = self.clientsock.recv(4096)

        print '-------------------------------\n'
        print self.clientinit
        print '\n-------------------------------'

        # Splitting the message on the separator character, terminating
        # if we get a unexpected message
        split_message = self.clientinit.split('|')
        if len(split_message)!=3:
            self.clientsock.send('Error')
            self.clientsock.close()
            raise Exception('Wrong message type')

        # Checking if the type is ClientInit and the cipher proposed
        # by the client is supported by the server, if yes, we start
        # the server_init procedure

        if split_message[0] == 'ClientInit' and split_message[2] in self.allowed_ciphers:
            self.client_nonce = split_message[1]
            self.client_cipher = split_message[2]

            # If the message is recognized, we launch server_init, where the server initiates
            # his variables and responds to the client
            self.server_init()
        else:
            self.clientsock.send('Error')
            self.clientsock.close()
            raise Exception('Unexpected message')

    def server_init(self):

        # Generating server nonce
        self.generate_server_nonce()

        # Reading from server certificate to send it to client
        with open (self.servercert, 'r') as data:
            server_certificate = data.read()

        # Generating the message for client, using | as delimiter, with the nonce, the acknowledgement
        # of the cipher and the server certificate  
        self.serverinit = 'ServerInit' + '|' + self.server_nonce + '|' + self.client_cipher + '|' + server_certificate

        if self.authentication == 'ClientAuth':
            self.serverinit = self.serverinit + '|' + 'CertReq'

        self.clientsock.send(self.serverinit)

        # We store serverinit without the cipher for the checksum message
        # (it's in the slide, but I wouldn't do this)
        self.serverinit = 'ServerInit' + '|' + self.server_nonce + '|' + server_certificate
        if self.authentication == 'ClientAuth':
            self.serverinit = self.serverinit + '|' + 'CertReq'





        # ------------------------------------------------------------------------------




        # Getting response from client to go on with the handshake procedure

        client_response = self.clientsock.recv(8192)
        print '-------------------------------\n'
        print client_response
        print '\n-------------------------------'

        # Splitting the message and checking if it is the expected type
        splitted_response = client_response.split('|')
        if not splitted_response[0] == 'ClientKex':
            self.clientsock.close()
            raise Exception('Unexpected message type')

        rsa_encrypted_pms = splitted_response[1]

        # If the authentication type requires the client cert:
        if self.authentication == 'ClientAuth':
            self.client_certificate = splitted_response[3]
            nonce_signature = splitted_response[4]

            # Checking client certs
            if not self.certificate_is_valid(self.client_certificate):
                self.clientsock.send('Invalid certificate')
                raise Exception('Invalid certificate')
                self.server_connection.close()

            # Checking if the received nonce is valid to prevent attacks

            client_pubkey = utils.read_pubkey_from_pem(self.client_certificate)


            
            if not utils.verify_signature(client_pubkey, nonce_signature, self.server_nonce + rsa_encrypted_pms):
                self.clientsock.send('Server nonce verification failed')
                raise Exception('Server nonce verification failed')
                self.server_connection.close()





        # Getting server's private key and decrypting the pms sent by the server
        # and encrypted with the server pubkey
        with open (self.serverprivatekey, 'r') as server_key:
            server_key_data=server_key.read()
        privkey = utils.read_privkey_from_pem(server_key_data)

        pre_master_secret = utils.decrypt_rsa(privkey, rsa_encrypted_pms)

        # Generating key couple
        key_1_payload = binascii.unhexlify(self.client_nonce + self.server_nonce + '00000000')
        key_2_payload = binascii.unhexlify(self.client_nonce + self.server_nonce + '11111111')
        self.key_1 = utils.create_hmac(pre_master_secret, key_1_payload)
        self.key_2 = utils.create_hmac(pre_master_secret, key_2_payload)

        
        # Check if message_checksum is legit, terminate and send back error to client
        # otherwise
        message_checksum = splitted_response[2]
        
        message_control = utils.create_hmac(
            self.key_2,
            self.clientinit + self.serverinit
            )


        if message_checksum != message_control:
            self.clientsock.send('Wrong message checksum')
            raise Exception('Wrong message checksum')
            self.clientsock.close()
            

        # Generate check for last msg and send it back
        if self.authentication == 'ClientAuth':
            _verifymessage = client_response.replace('|' + splitted_response[4], '')
        else:
            _verifymessage = client_response

        server_message_checksum = utils.create_hmac(self.key_2, _verifymessage)

        self.clientsock.send(server_message_checksum)

        self.handshake_done = True


    def certificate_is_valid(self, pemstring):

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

        return is_not_expired and is_valid

    def generate_server_nonce(self):
        self.server_nonce = binascii.hexlify(utils.generate_nonce())


        


main()