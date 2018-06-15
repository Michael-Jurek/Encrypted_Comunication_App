# Encrypted_Comunication_App
Python Application for Encrypted Comunication

## ABOUT
This app was a student project at FEEC BUT BRNO in the subject of Applied Cryptography. Type of communication is double server - client communication, where Certificate Atuhority(CA) is server, signs clients public keys, Bob acts as a server and Alice as a client (passicely response on chalanges)

## Certificate Authority Principle (CA)
CA generates RSA couple of keys, public and private. Public key is available for everyone. So Client will generate couple also and connect to CA with his public key (str_Kpub = str(Kpub.exportKey('PEM')).
CA generates certificate sig_Kpub = rsa.sign(Kpub, KprivateCA).

## Communication Principle
Once all parts have own certificates, they can negotiate key for Asymetric Cryptography. Bob switches to listening state, and Alice switches to client state. Alice generates Kaes (Key for AES-256) and send it to Bob.
Encryption process can begin.

## INSTALATION
Download Python 3.6 and Anaconda Environment (Modul PublicKey and Crypto - not available on Windows OS)
https://www.anaconda.com/download/


## RUN
Run only on LINUX OS
1) Start CA.py, Alice.py and Bob.py
2) Press 1 to Generate key couple, and on Alice side pres 0 and write some secret message to Bob
3) On CA press 2, and on other client press 2 also to generate signatures
4) On Alice and Bob sides press 3 to validate signatures; if everything ok, continue
5) Press 4 on Bob side to start negotiating key for AES-256, also press 4 on Alice side; then press Enters to continue...
6) On Bob side press 5 to start listenning for a file, on Alice side press 6 to send file
