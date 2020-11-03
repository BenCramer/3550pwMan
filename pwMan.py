# Josh Talkington
# jt0190@unt.edu
# 9/25/2019
#
# This program stores passwords in a file 
# that is encrypted with a master password
#
# system packages: gcc libffi-devel python-devel openssl-devel
# python packages: pycryptodome 
# Tested on Fedora 30 with Python 2.7.16
#
# references:
#   1. https://stackoverflow.com/questions/19232011/convert-dictionary-to-bytes-and-back-again-python
#   2. https://www.pycryptodome.org/en/latest/src/examples.html
# 
# To run:
#	python pwMan.py Google.com
# 
# To reset:
# 	rm passwords
#
# Example Output:
# $ python pwMan.py Google.com
# 	Enter Master Password: pass
# 	No password database, creating....
# 	Loading database...
# 	No entry for  Google.com , creating new...
# 	Generated pass: ,e]P5i%{av
# 	stored
# $ python pwMan.py Google.com
# 	Enter Master Password: pass
# 	Loading database...
# 	website:   Google.com
# 	password:  ,e]P5i%{av

# Updated 9 October 2019 by Peyton Pritchard
# Updated to Python 3.7.4
# Edited 2 November 2020 by Ben Cramer, Blake Cox, and Jacob Butler

import csv, os, sys, json, string, random
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2

passwordFile = "passwords"
##The salt value should be set here.
salt = "bcbcjb,kmmdvpasd"
##The header of the file.
head = " ____               __  __\n"+"|  _ \ __ _ ___ ___|  \/  | __ _ _ __  \n" +"| |_) / _` / __/ __| |\/| |/ _` | '_ \ \n" +"|  __/ (_| \__ \__ \ |  | | (_| | | | |\n" +"|_|   \__,_|___/___/_|  |_|\__,_|_| |_|\n"

# Generates a random password to be used for a newly-registered site.
def generatePass():
	charset = string.printable
	passw = ''
	for x in range(0,17):
		passw += random.choice(charset)

	return passw

# Converts the dictionary to and from bytes, necessary for encryption/decryption.
def dictToBytes(dict):
	return json.dumps(dict).encode('utf-8')
def bytesToDict(dict):
	return json.loads(dict.decode('utf-8'))


# Encrypt the dictionary 'dict' using the key 'k' in AES' EAX mode. Writes the encrypted data to the passwordfile.
def encrypt(dict, k):
	##Define the encryption scheme here.
	cipher = AES.new(k, AES.MODE_EAX)

	##Encrypt the dictionary value here.
	ciphertext, tag = cipher.encrypt_and_digest(dict)

	with open(passwordFile, 'wb') as outfile:
		[outfile.write(x) for x in (cipher.nonce, tag, ciphertext)]

# Decrypt the passwordFile with the key 'k' using AES' EAX mode. Returns the bytes of the file.
def decrypt(k):
	with open(passwordFile, 'rb') as infile:
		nonce, tag, ciphertext = [infile.read(x) for x in (16, 16, -1)]
		##Define the encryption scheme here.
		cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)

		##Decrypt the ciphertext here.
		data = cipher.decrypt(ciphertext)

		return data


def Main():

	print("\n\n")
	mpw = input("Enter Master Password: ")
	k = PBKDF2(mpw, str.encode(salt), dkLen=32) # derive key from password using our salt value
	
	# check for password database file
	if not os.path.isfile(passwordFile):
		
		# create new passwords file
		print("No password database, creating....")
		newDict = dictToBytes({"": ""})
		encrypt(newDict, k)

	# check usage
	if len(sys.argv) != 2:
		print("usage: python pwMan.py <website>")
		return
	else:

		# decrypt passwords file to dictionary
		try:
			print("Loading database...")
			pws = decrypt(k)
			pws = bytesToDict(pws)

		except Exception as e:
			print("Wrong password")
			return

		# print value for  website or add new value
		entry = sys.argv[1]
		if entry in pws:
			print("entry   : " + str(entry))
			print("password: " + str(pws[entry]))
		else:
			print("No entry for " + str(entry) + ", creating new...")
			# Generate a new password for the designated site.
			newPass = generatePass()
			print("Generated pass: " + newPass)

			# Add newPass to the dictionary, then encrypt it
			pws[entry] = newPass
			encrypt( dictToBytes(pws), k)
			print("stored")


if __name__ == '__main__':
	print(str(head))
	Main()

