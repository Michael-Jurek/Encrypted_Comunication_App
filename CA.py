#################################################################################################################
#                                                                                                               #
#           Project: Encrypted client-client communication, with trusted Certification Authority                #
#                                                Summer Term 2018                                               #
#					       	 					  FEEC BUT BRNO													#
#																												#
#           Credits: Michael Jurek, @mikedevop                       											#
#################################################################################################################

from base64 import b64encode, b64decode
import socket, os, sys, pickle, datetime, time, traceback, logging
import RSAlib as rsa
import AESlib as aes
from colorama import init, Fore 
init()

def signCertificate(s, host, port, KprCA, KpubCA):
	print("listening...")
	s.listen(5)

	conn, addr = s.accept()
	print("Connection from: " + str(addr))

	while True:
		KpubK = conn.recv(1024).decode()
		if not KpubK:
			break

		sig_KpubK = b64encode(rsa.sign(KpubK.encode(), KprCA))

		conn.send(pickle.dumps(sig_KpubK))
		conn.send(pickle.dumps(KpubCA))

def Main():
	host = "127.0.0.1"
	port = 5000
	KpubCA = KprCA = ''
	newtime = ''

	while True:
		os.system('clear')
		print("Certiciate authority " + Fore.LIGHTCYAN_EX + "[Trusted server]" + Fore.RESET)
		print("====================================================")
		print("1 - Generate RSA-2048 key couple")
		if KpubCA and KprCA:
			print("\ta - Write private key")
			print("\tb - Write public key")
		print("2 - Sign Clients public key")
		print("q - EXIT")
		print("====================================================")

		number = input("-> ")

		if KpubCA and KprCA:
			if number == 'a':
				print(KprCA.exportKey('PEM'))
				input("\n Generated at: " + newtime)
			elif number == 'b':
				print(KpubCA.exportKey('PEM'))
				input("\n Generated at: " + newtime)
		if number == '1':
			(KpubCA, KprCA) = rsa.newKeys(1024)
			newtime = datetime.datetime.now().strftime('%H:%M:%S %d-%m-%Y')
			input("Key generation process was succesfull")
		elif number == '2':
			if not KpubCA or not KprCA:
				input("\n[ERROR]\nRSA keys are not evailable\n")
				continue
			mySocket = socket.socket()
			mySocket.bind((host, port))

			try:
				signCertificate(mySocket, host, port, KprCA, KpubCA)
			except socket.error:
				input("\n[ERROR]\nCan not connect to server\n")
			except:
				logging.error(traceback.format_exc())
				input("\nConnection was interupted")
				continue
			mySocket.close()
			input("\n Certificate was published")
		elif number == 'q':
			break

if __name__ == '__main__':
	Main()