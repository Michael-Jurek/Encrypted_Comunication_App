#################################################################################################################
#                                                                                                               #
#           Project: Encrypted client-client communication, with trusted Certification Authority                #
#                                             Summer Term 2018	                                                #
#					       	  				    FEEC BUT BRNO	 												#
#																												#
#           Credits: Michael Jurek, @mikedevop                       											#
#################################################################################################################

from base64 import b64encode, b64decode
import socket, os, sys, pickle, datetime, time, traceback, logging
import RSAlib as rsa
import AESlib as aes
from colorama import init, Fore 
init()

def stripNANChars(str):							#function for cleaning str
	"""
	Function that strips not a number chars
	"""
	str = str.replace("b","")
	str = str.replace("'","")
	str = str.replace("\\r\\n","\r\n")
	return str

def AESEncryptFile(key, inFile, outFile=None, chunkSize=64*1024):
	"""
	Function that encrypts file inFile with key
	"""
	if not outFile:
		outFile = (inFile.rstrip(".txt") + ".enc")
	with open(inFile, 'rb') as inputF:
		with open(outFile, 'wb') as outF:
			while True:
				chunk = inputF.read(chunkSize)
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk = aes.padData(chunk)
				chunk = stripNANChars(str(chunk))
				outF.write(aes.encrypt(chunk, key))

def AESDecryptFile(key, inFile, outFile, chunkSize=64*1024):
	"""
	Function that decrypts file inFile
	"""
	with open(inFile, 'rb') as inutF:
		with open(outFile, 'w') as outF:
			while True:
				chunk = inputF.read(chunkSize)
				if len(chunk)==0:
					break
				outF.write(aes.decrypt(chunk, key).decode('utf-8'))

def getCertificate(s, host, port, KpubK):
	"""
	Function that generates certificate
	"""
	s.connect((host,port))
	s.send(KpubK.encode())

	sig_KpubK = pickle.loads(s.recv(1024))

	KpubCA = pickle.loads(s.recv(1024))
	return sig_KpubK, KpubCA

def changeCertificatesAlice(s, host, port, KpubA, sig_KpubA, KpubCA, newtime):
	s.connect((host,port))
	print("\n Sending my public key (KpubA)")
	s.send(pickle.dumps(KpubA))

	print("\n Sending my certificate (sig_KpubA)\n")
	input("Press any key to continue...\n")
	s.send(pickle.dumps(sig_KpubA))

	print("\n Sending time stamp: \n")
	input("Press any key to continue...")
	s.send(newtime.encode())


	str_KpubB = pickle.loads(s.recv(1024))
	print("\n [String] Received Bob's public key (str_KpubB)")

	KpubB = pickle.loads(s.recv(1024))
	print("\n [Pickle] Received Bob's public key (KpubB)")

	sig_KpubB = pickle.loads(s.recv(1024))
	print("\n Received Bob's certificate")

	trustConfirm = rsa.verify(str_KpubB.encode(), b64decode(sig_KpubB), KpubCA)

	s.close()

	mySocket = socket.socket()
	mySocket.connect((host,port))

	timeBob = mySocket.recv(128).decode()

	mySocket.close()

	return str_KpubB, KpubB, sig_KpubB, trustConfirm, timeBob

def setAESKey(s, host, port, KpubB):
	Kaes = aes.genKey()
	print("\n" + str(Kaes) + "\n")

	s.connect((host,port))

	encrypted = b64encode(rsa.encrypt(Kaes, KpubB))
	s.send(encrypted)

	print("\n Private key for AES was encrypted and send (Kaes)")

	reply = s.recv(1024).decode()
	input("\n Answer received: " + reply)

	return Kaes

def recvFile(s, file):
	with open(file, 'wb') as f:
		while True:
			data = s.recv(1024)
			if not data:
				break
			f.write(data)

def sendFile(s, file):
	with open(file, 'rb') as f:
		chunk = f.read(1024)
		while chunk:
			s.send(chunk)
			chunk = f.read(1024)

def validateFile(mySocket, host, port, path):
	mySocket.connect((host,port))
	encryptedDoc = (path.rstrip(".txt") + ".enc")
	try:
		sendFile(mySocket, encryptedPrimes)
	except:
		logging.error(traceback.format_exc())
		input()
	print("\n File was encrypted and send succesfully. [com.txt]")
	mySocket.close()
	input("\n Press any key to continue ...")

	mySocket = socket.socket()
	mySocket.connect((host, port))

	recvFile(mySocket, "resultEncrypted.enc")

	mySocket.close()

def showFile(file):
	with open(file, 'r') as f:
		chunk = f.read(1024)
		while chunk:
			print(chunk)
			chunk = f.read(1024)
	input("End of File")	


def makeFile():										#function for creating chat file
	path = "chat.txt"

	file = open(path,"w+")
	text = input("Write your message to Bob:\n")
	file.write(text)
	file.close()

	input("\nText was saved to " + path)
	return path

def Main():
	host = '127.0.0.1'								#Clients IP address
	port1 = 5000									#CA port for singing keys
	port2 = 5052									#Bobs port for sending a file
	port3 = 5053 									#Port for AES key negotiation 
	port4 = 5054									#Port for validating a file
	KpubA = Kpra = ''								#Public key and Private key initialization
	trustConfirm = False							#if false establish truste between Alice and Bob
	path = ''										#File path false as default
	Kaes = ''										#Key incialization for symetric cryptography

	while True:										#Main managing cycle
		os.system('clear')							#Clean screen

		if not trustConfirm:
			print("Alice")
		else:
			print("Alice " + Fore.LIGHTGREEN_EX + "[Bob truste]" + Fore.RESET)
		print("=====================================================================")
		print("0 - Generate file for encryption (chat.txt)")	
		if path:
			print("\tp - Print file")
		print("1 - Generate RSA-2048 key couple")

		if KpubA and KprA:
			print("\ta - Print private key")
			print("\tb - Print public key")
		print("2 - Let sign my public key at CA")
		print("3 - Validate my signed public key at CA")
		print("4 - Connect to Bob, send sig_KpubA and wait for sig_KpubB")
		if trustConfirm:
			print("\tc - Print Alices public key")
			print("---------------------------------------")
			print("5 - Negotiate secret key for AES")

			if Kaes:
				print("\tk - Print secret key for AES")
			print("6 - Send a file")

		print("=====================================================================")

		number = input("-> ")

		if KpubA and KprA:
			if number == 'a':
				print(KprA.exportKey('PEM'))
				input("\n Generated in time: " + newtime)
			elif number == 'b':
				print(KpubA.exportKey('PEM'))
				input("\n Generated in time:" + newtime)
		if path:
			if number == 'p':
				try:
					showFile(path)
				except:
					logging.error(traceback.format_exc())
					input()
		if trustConfirm:
			if Kaes:
				if number == 'k':
					input(Kaes)
			if KpubB:
				if number == 'c':
					print("Print Bobs public Key")
					print(KpubB.exportKey('PEM'))
					input("\n Generated in time: " + timeBob)
			mySocket = socket.socket()
		if number == '5':
			try:
				Kaes = setAESKey(mySocket, host, port3, KpubB)	#key for symetric cryptography
			except:
				logging.error(traceback.format_exc())
				input()
			mySocket.close()
		if number == '6':
			if path and Kaes:
				AESDecryptFile(Kaes, path)
			else:
				input("\n[ERROR]\nFile or private key for AES was not found")
				continue
			try:
				validateFile(mySocket, host, port4, path)
				AESDecryptFile(Kaes, "receivedEncrypted.enc", "received.txt")
			except socket.error:
				input("\n[ERROR]\nCannot communicate with server")
				continue
			except:
				logging.error(traceback.format_exc())
				input()
				continue

			input("\nFile was received and decrypted [received.txt]")
		if number == '0':
			try:
				path = makeFile()
			except:
				input("\n[ERROR]\nNothing inserted")
		elif number == '1':
			(KpubA, KprA) = rsa.newKeys(1024)
			newtime = datetime.datetime.now().strftime('%H:%M:%S %d-%m-%Y')
			input("Key generation was succesfull")
		elif number == '2':
			mySocket = socket.socket()
			try:
				str_KpubA = str(KpubA.exportKey('PEM'))	
				sig_KpubA, KpubCA = getCertificate(mySocket, host, port1, str_KpubA)
			except EOFError:
				input("\n[ERROR]\nConnection was lost\n")
			except AttributeError:
				input("\n[ERROR]\nRSA keys are not available\n")
			except socket.error:
				input("\n[ERROR]\nCan not connect to server\n")
			mySocket.close()
		elif number == '3':
			try:
				verify = rsa.verify(str_KpubA.encode(), b64decode(sig_KpubA), KpubCA)
				input("Validation was: " + str(verify))
			except UnboundLocalError:
				input("\n[ERROR]\nCertificate, signature or CA public key is not available\n")
		elif number == '4':
			mySocket = socket.socket()
			try:
				str_KpubB, KpubB, sig_KpubB, trustConfirm, timeBob = changeCertificatesAlice(mySocket, host, port2, str_KpubA, sig_KpubA, KpubCA, newtime)
				if trustConfirm:
					print("\nBobs Certificate validation -> " + Fore.LIGHTGREEN_EX + str(trustConfirm) + Fore.RESET)
				else:
					print("\nBobs Certificate validation -> " + Fore.LIGHTRED_EX + str(trustConfirm) + Fore.RESET)
				input()
			except socket.error:
				input("\n[ERROR]\nCan not connect to server")
				continue
			except EOFError:
				input("\n[ERROR]\nOther part untimely end up connection")
				continue
			except UnboundLocalError:
				logging.error(traceback.format_exc())
				input()
		elif number == 'q':
			break


if __name__ == '__main__':
	Main()