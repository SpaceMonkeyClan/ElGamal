# CS4600 Project - ElGamal Encryption/Decryption Tool

import sys
import argparse
from random import randint
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--encrypt', required=False, action='store_true', help='Option to encrypt')
	parser.add_argument('-a', '--alfa_parameter', required=True, action='store', help='Parameter alfa')
	parser.add_argument('-p', '--p_parameter', required=True, action='store', help='Parameter p')
	parser.add_argument('-B', '--B_parameter', required=False, action='store', help='Parameter B (public)')
	
	parser.add_argument('-d', '--decrypt', required=False, action='store_true', help='Option to decrypt')
	parser.add_argument('-b', '--b_parameter', required=False, action='store', help='Parameter B (secret)')
	parser.add_argument('-ke','--ephemeral_key', required=False, action='store', help='Ephemeral key')

	parser.add_argument('-si', '--sign', required=False, action='store_true', help='Option to sign')
	parser.add_argument('-v', '--verify', required=False, action='store_true', help='Option to verify signature')
	parser.add_argument('-r', '--r_parameter', required=False, action='store', help='Parameter r')
	parser.add_argument('-s', '--s_parameter', required=False, action='store', help='Parameter s')

	parser.add_argument('-m', '--message', required=True, action='store', help='Message (to encrypt or decrypt)')
	parser.add_argument('-vv', '--verbose', required=False, action='store_true', help='Allow debugging')
	return parser.parse_args()


def encrypt(Kpub, message, debug=False):
	p, alfa, B = Kpub
	a = randint(0, p) # = 4
	# Ephemeral key calculation ->      privKey = (alfa^r)mod(p)
	Ke = pow(alfa, a, p)
	# Shared key calculation ->         encryptKey = (B^r)mod(p)
	K = pow(B,a,p)
	# Encrypted message calculation ->  cipher = (encryptKey*p)mod(p)
	y = (message*K) % p
	# Bob sends the ephemeral key and the encrypted message (Ke, y)
	sent_values = (Ke, y)
	if debug:
		print ("Plaintext message:       "  + str(message) )
		print ("Public key:              (" + str(p) + "," + str(alfa) + "," + str(B) + ")" )
		print ("Shared key (K):          "  + str(K) )
		print ("Ephemeral key:           "  + str(Ke) )
		print ("Encrypted message:       "  + str(y) )
		print ("Bob sends (Ke,y):        (" + str(Ke) + "," + str(y) + ")" )
	return sent_values


def decrypt(Kpriv, encrypted_message, debug=False):
	p, alfa, b = Kpriv
	Ke, y = encrypted_message
	# Shared key calculation ->         sharedKey = (publicKey^s)mod(p)
	K = pow(Ke,b,p)
	# Decrypted message calculation ->  decryptKey = (p * (sharedKey^(-1)) mod(p)
	x = (y*inverse(K, p)) % p
	if debug:
		print ("Private key:             (" + str(p) + "," + str(alfa) + "," + str(b) + ")" )
		print ("Alice receives (Ke,y):   (" + str(Ke) + "," + str(y) + ")" )
		print ("Shared key (K):          "  + str(K) )
		print ("Decrypted message:       "  + str(x) )
	return x


def sign(Kpriv, message, debug=False):
	p, alfa, b = Kpriv
	# Ephemeral key is random
	Ke = randint(0, p-2) # = 31
	# Parameter r calculation ->        r = (alfa^Ke)mod(p)
	r = pow(alfa, Ke, p)
    # Parameter s calculation ->        s = ((m-b*r)*Ke^(-1))mod(p-1) 
	s = ( (message-b*r) * inverse(Ke,(p-1)) ) % (p-1)
	signature = (r,s)
	if debug:
		print ("Private key:             (" + str(p) + "," + str(alfa) + "," + str(b) + ")" )
		print ("Ephemeral key:           "  + str(Ke) )
		print ("Signature (r,s):         (" + str(r) + "," + str(s) + ")" )
	return signature


def verify(Kpub, message, signature, debug=False):
	p, alfa, B = Kpub
	r, s = signature
	# Parameter t calculation ->        t = ((B^r*r^s))mod(p)
	t = ( pow(B, r) * pow(r, s)) % p
	# Comparison between parameter t and (alfa^m)mod(p)
	verification = (t == (pow(alfa, message, p)))
	if debug:
		print ("Plaintext message:       "  + str(message) )
		print ("Public key:              (" + str(p) + "," + str(alfa) + "," + str(B) + ")" )
		print ("Signature (r,s):         (" + str(r) + "," + str(s) + ")" )
		print ("Calculated t:            "  + str(t) )
		print ("Verification:            "  + str(verification) )
	return verification


def encrypt_help():
	print("Incorrect arguments. Example:")
	print("python3 main.py --encrypt -p 79 -a 30 -B 59 -m 44 -vv")
	sys.exit(1)


def decrypt_help():
	print("Incorrect arguments. Example:")
	print("python3 main.py --decrypt -p 79 -a 30 -b 61 -m 73 -ke 13 -vv")
	sys.exit(1)


def sign_help():
	print("Incorrect arguments. Example:")
	print("python3 main.py --sign -p 541 -a 128 -b 105 -m 95 -vv")
	sys.exit(1)


def verify_help():
	print("Incorrect arguments. Example:")
	print("python3 main.py --verify -p 541 -a 128 -B 239 -m 95 -r 280 -s 65 -vv")
	sys.exit(1)


def create_kpub(p, alfa, B):
	p =      int(p)
	alfa =   int(alfa)
	B =      int(B)
	Kpub  = (p, alfa, B) # Bob makes B public
	return Kpub


def create_kpriv(p, alfa, b):
	p =      int(p)
	alfa =   int(alfa)
	b =      int(b)
	Kpriv = (p, alfa, b) # Bob keeps b secret
	return Kpriv


def main():
	myargs = get_args()
	debug =  myargs.verbose
	m =      int(myargs.message)
	
	if myargs.encrypt:
		p =      myargs.p_parameter
		alfa =   myargs.alfa_parameter
		B =      myargs.B_parameter
		if (p is None) or (alfa is None) or (B is None):
			encrypt_help()
		Kpub = create_kpub(p, alfa, B)
		encrypted_message = encrypt(Kpub, m, debug)
		print(encrypted_message)
	
	elif myargs.decrypt:
		p =      myargs.p_parameter
		alfa =   myargs.alfa_parameter
		b =      myargs.b_parameter
		Ke =     myargs.ephemeral_key
		if (p is None) or (alfa is None) or (b is None) or (Ke is None):
			decrypt_help()	
		Kpriv = create_kpriv(p, alfa, b)
		Ke =    int(Ke)
		encrypted_message = (Ke, m)
		decrypted_message = decrypt(Kpriv, encrypted_message, debug)
		print(decrypted_message)
	
	elif myargs.sign:
		p =      myargs.p_parameter
		alfa =   myargs.alfa_parameter
		b =      myargs.b_parameter
		if (p is None) or (alfa is None) or (b is None):
			sign_help()	
		Kpriv = create_kpriv(p, alfa, b)
		signature = sign(Kpriv, m, debug)
		print(signature)

	elif myargs.verify:
		p =      myargs.p_parameter
		alfa =   myargs.alfa_parameter
		B =      myargs.B_parameter
		r =      myargs.r_parameter
		s =      myargs.s_parameter
		if (p is None) or (alfa is None) or (B is None) or (r is None) or (s is None):
			verify_help()
		Kpub = create_kpub(p, alfa, B)
		r =      int(r)
		s =      int(s)
		signature = (r, s)
		verification = verify(Kpub, m, signature, debug)
		print(verification)


if __name__ == "__main__":
    main()
{"mode":"full","isActive":False}