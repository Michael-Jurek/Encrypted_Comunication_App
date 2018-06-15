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
	with open(inFile, 'rb') as inputF:
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

def changeCertificatesBob(s, host, port, str_KpubB, KpubB, sig_KpubB, KpubCA, newtime):
	print("listening...")
	s.listen(5) 
	conn, addr = s.accept()
	print("Connection from: " + str(addr))

	KpubA = pickle.loads(conn.recv(1024))
	print("\nReceived public key from Alice (KpubA)")

	sig_KpubA = pickle.loads(conn.recv(1024))
	print("\nReceived certificate from Alice (sig_KpubA)")

	timeAlice = conn.recv(128).decode()

	trustConfirm = rsa.verify(KpubA.encode(), b64decode(sig_KpubA), KpubCA)
	if trustConfirm:
		print("\nAlice Certificate validation -> " + Fore.LIGHTGREEN_EX + str(trustConfirm) + Fore.RESET)
	else:
		print("\nAlice Certificate validation -> " + Fore.LIGHTRED_EX + str(trustConfirm) + Fore.RESET)
	input("Press key to continue...")

	if not trustConfirm:
		conn.close()
		return False

	print("\n[Pickle] Sending my public key (str_KpubB)")
	conn.send(pickle.dumps(str_KpubB))
	time.sleep(0.5)

	print("\n[byteString] Sending my public key (KpubB)")
	conn.send(pickle.dumps(KpubB))
	time.sleep(0.5)

	print("\nSending my certificate (sig_KpubB)")
	conn.send(pickle.dumps(sig_KpubB))

	time.sleep(0.5)
	conn.close()

	s.listen(5)
	conn, addr = s.accept()
	conn.send(newtime.encode())
	conn.close()

	input("\nOK, Press any key to continue...")

	return KpubA, sig_KpubA, trustConfirm, timeAlice

def setAESKeyBob(s, host, port, KprB):
	print("listening...")
	s.listen(5)

	conn, addr = s.accept()
	print("Connection from: " + str(addr))

	received = conn.recv(1024).decode()
	if not received:
		return False
	print("\nSecret key for AES was accepted and decrypted (Kaes)")

	Kaes = KprB.decrypt(b64decode(received))

	conn.send("OK".encode())
	input("\nAnswer send: OK")

	return Kaes

def pathsToFiles():
	i = 1
	filename = os.path.dirname(__file__)
	while True:
		relPathChunk = '\\receivedFiles\\Check_' + str(i) + '\\'
		relPath = filename + relPathChunk
		if os.path.exists(os.path.dirname(relPath)):
			i += 1
			continue
		else:
			break
	os.mkdir(relPath)
	pathEncrypted = relPath + 'encryptedDoc.enc'
	pathDecrypted = relPath + 'decryptedDoc.txt'
	pathResult = relPath + 'answer.txt'
	pathResultEnc = relPath + 'answerEncrypted.enc'

	return pathEncrypted, pathDecrypted, pathResult, pathResultEnc, relPathChunk

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

def readFile(inFile, outFile):
	text = input("\nWrite some answer\n")
	with open(inFile, "r") as inputF:
		with open(outFile, "w") as outF:
			for line in inputF:
				if not line:
					break
				else:
					outF.write(text)
					break

def validateFile(mySocket, Kaes):
	print("listening...")
	mySocket.listen(5)

	conn, addr = mySocket.accept()
	print("Connection from: " + str(addr))

	pathEncrypted, pathDecrypted, pathResult, pathResultEnc, relPathChunk = pathsToFiles()

	recvFile(conn, pathEncrypted)
	conn.close()

	try:
		AESDecryptFile(Kaes, pathEncrypted, pathDecrypted)
		print("\nFile was received and decrypted [." + relPathChunk + "\\dectedDoc.txt]")
	except UnboundLocalError:
		input("\n[ERROR]\nSecret key for AES is not available\n")
		return
	except:
		logging.error(traceback.format_exc())
		input()

	readFile(pathDecrypted, pathResult)
	print("\nFile with answer was created [." + relPathChunk + "\\answer.txt")

	try:
		AESEncryptFile(Kaes, pathResult, pathResultEnc)
	except:
		logging.error(traceback.format_exc())
		input()

	mySocket.listen(5)
	conn, addr = mySocket.accept()

	sendFile(conn, pathResultEnc)

	input("\nFile with answer was encrypted and sent [." + relPathChunk + "\\answerEncrypted.enc")

	conn.close()

def Main():
	host = '127.0.0.1'
	port1 = 5000
	port2 = 5052
	port3 = 5053
	port4 = 5054
	KpubB = KprB = ''
	trustConfirm = ''
	numberOfValidation = 1
	Kaes = ''
	evilDetected = False

	while True:
		os.system('clear')
		if not trustConfirm:
			if not evilDetected:
				print("Bob")
			else:
				print("Bob" + Fore.LIGHTRED_EX + "[Looks like evil]" + Fore.RESET)
		else:
			print("Bob " + Fore.LIGHTGREEN_EX + "[Alice validated]" + Fore.RESET)
		print("=====================================================================")
		print("1 - Generate RSA-2048 key couple")
		if KpubB and KprB:
			print("\ta - Write private key")
			print("\tb - Write public key")
		print("2 - Let sign my public key at CA")
		print("3 - Validate my signed public key at CA")
		print("4 - Let be a server and wait for sig_KpubA and send sig_KpubB")
		if trustConfirm:
			print("\tc - Print Bobs public key")
			print("---------------------------------------")
			print("5 - Negotiate secret key for AES")

			if Kaes:
				print("\tk - Print secret key for AES")
			print("6 - SEnd a file")

		print("=====================================================================")

		number = input("-> ")

		if KpubB and KprB:
			if number == 'a':
				print(KprB.exportKey('PEM'))
				input("\n Generated in time: " + newtime)
			elif number == 'b':
				print(KpubB.exportKey('PEM'))
				input("\n Generated in time: " + newtime)
		if trustConfirm:
			if Kaes:
				if number == 'k':
					input(Kaes)
			if KpubA:
				if number == 'c':
					print("Alice Public Key: ")
					print(KpubA)
					input("\n Generated in time: " + timeAlice)
			mySocket = socket.socket()
			if number == '5':
				mySocket.bind((host, port3))
				try:
					Kaes = setAESKeyBob(mySocket, host, port3, KprB)
				except:
					logging.error(traceback.format_exc())
					input()
				mySocket.close()
			elif number == '6':
				mySocket.bind((host, port4))
				try:
					validateFile(mySocket, Kaes)
				except:
					logging.error(traceback.format_exc())
					input()
		if number == '1':
			(KpubB, KprB) = rsa.newKeys(1024)
			newtime = datetime.datetime.now().strftime('%H:%M:%S %d-%m-%Y')
			input("Key generation was succesfull")
		elif number == '2':
			mySocket = socket.socket()
			try:
				str_KpubB = str(KpubB.exportKey('PEM'))
				sig_KpubB, KpubCA = getCertificate(mySocket, host, port1, str_KpubB)
			except EOFError:
				input("\n[ERROR]\nConnection was lost")
			except AttributeError:
				input("\n[ERROR]\nRSA keys are not available")
			except socket.error:
				input("\n[ERROR]\nCan not connect to server\n")
			mySocket.close()
		elif number == '3':
			try:
				verify = rsa.verify(str_KpubB.encode(), b64decode(sig_KpubB), KpubCA)
				input("Validation was: " + str(verify))
			except UnboundLocalError:
				input("\n[ERROR]\nCertificate is not available\n")
		elif number == '4':
			mySocket = socket.socket()
			mySocket.bind((host, port2))
			try:
				KpubA, sig_KpubA, trustConfirm, timeAlice = changeCertificatesBob(mySocket, host, port2, str_KpubB, KpubB, sig_KpubB, KpubCA, newtime)
			except TypeError:
				input("\n[ERROR]\nCertificate is not trustable. Ending connection...\n")
				trustConfirm = ''
				evilDetected = True
			except UnboundLocalError:
				input("\n[ERROR]\nRSA keys or certificate is not available\n")
			except:
				logging.error(traceback.format_exc())
				input()
			mySocket.close()
		elif number == 'q':
			break

if __name__ == '__main__':
	Main()
