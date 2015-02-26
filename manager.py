from crypto import CCrypto  #my crypto class
from Crypto import Random   #pycryto class (Case is important!!)
import sys, os
import getpass
import hashlib

#GLOBALS
HELP_CMD = '-h'
SAVE_CMD = '-S'
GET_CMD = '-G'

#----- OUTPUT FUNCTIONS ------#
def printSuccess(username, password):
	print "--------------------------------"
	print "Username: %s \nPassword: %s" % (username, password)
	print "--------------------------------"

def printFailure():
	print 'Failed!' 

def printError():
	print "[Help:] python %s -h" % sys.argv[0]
	sys.exit(1)

def printHelp():
	print "\n--- Usage ---"
	print "[Storing:] python %s <method> <username> <password> <options>" % sys.argv[0]
	print "[Example:] python %s -S us3rname passw0rd -c" % sys.argv[0]
	print "\n[Retrieving:] python %s <method> <username> <options>" % sys.argv[0]
	print "[Example:] python %s -G us3rname -c" % sys.argv[0]
	print "\nMethods: "
	print "-S  -  Save a username and password"
	print "-G  -  Retrieve a password by username"
	print "No default method. One of the above methods must be selected."
	print "\nOptions: "
	print "-e  -  EBC Mode (Insecure)"
	print "-r  -  CTR Mode"
	print "-c  -  CBC Mode (Recommended, Default)"
	print "\nMaster Password: "
	print "- You will be prompted to enter a master password to generate your AES key."
	print "- The master password is set the first time the program is run."
	print "- The same master password must then be used for future encryption/decryption.\n"
	sys.exit(1)

#-------- USER CREDENTIAL FUCNTIONS --------#
def padPassword(password):  
	size = 0x40  # 64 bytes - pads 128 hex characters
	frontStr = Random.new().read(size).encode('hex')
	backStr = Random.new().read(size).encode('hex')
	padded = frontStr + password + backStr
	return padded

def unpadPassword(password):
	size = 0x40 * 2 # must double the size as padPassword()
	unpaded = password[size:-size]
	return unpaded

def getMasterPassword():
	password = getpass.getpass("Password:") #hidden input
	firsthash = passHash = hashlib.sha256(password).hexdigest()

	for i in range(0, 10000): 	#more iterations, more difficult to brute force
		passHash = hashlib.sha256(passHash).hexdigest() 

	if not os.path.isfile('hash.txt'):
		repassword = getpass.getpass("Reenter Password:") 
		if password != repassword:
			print "Error: Passwords do not match!"
			sys.exit(1)
		
		ofl = open('hash.txt', 'w')	
		ofl.write(passHash)
		ofl.close()	

	ifl = open('hash.txt', 'r')
	fileHash = ifl.readline().rstrip('\n')

	if fileHash != passHash:
		print "Sorry, an incorrect password was entered!"
		sys.exit(1)

	return firsthash  # hash is more secure than the plaintext password

def saveCredentials(username, password, option='-c'):
 	option = option[1:].lower()   #blank option wont cause a problem
	if len(option) != 1:
		printHelp()
	
	try:
		with open('passwd.txt') as ifl:
			for line in ifl:
				line = line.rstrip('\n')
				(uname, cipher, option) = line.split('|')
				if uname == username:
					return 1
	except:
		pass

	cc = CCrypto(option)
	masterpass = getMasterPassword()
	cc.setPassword(masterpass)

	paddedPassword = padPassword(password) #pad password for more encryption blocks
	filestr = username + '|' + cc.encrypt(paddedPassword) + '|' + option + '\n'

	ofl = open('passwd.txt', 'a')
	ofl.write(filestr)
	ofl.close()


def getCredential(username):
	nameNotFound = True
	try:
		with open('passwd.txt') as ifl:
			for line in ifl:
				line = line.rstrip('\n')
				(uname, cipher, option) = line.split('|')
				if uname == username:
					nameNotFound = False
					break;
	except:
		print "Error: You have not saved any creditials yet."
		sys.exit(1)

	if nameNotFound:
		print "Error: The username '%s' was not found." % username
		sys.exit(1)

	cc = CCrypto(option)
	masterpass = getMasterPassword()
	cc.setPassword(masterpass)

	password = unpadPassword(cc.decrypt(cipher))
	return password


#------- MAIN --------#
if __name__ == '__main__':
	if len(sys.argv) < 2 or len(sys.argv) > 5:
		printError()

	if sys.argv[1][:2].lower() == HELP_CMD:
		printHelp()

	elif sys.argv[1].upper() == SAVE_CMD:
		opt = ""
		if len(sys.argv) < 4 or len(sys.argv) > 5:
			printError()
		elif len(sys.argv) == 5:
			opt = sys.argv[4]

		err = saveCredentials(sys.argv[2], sys.argv[3], opt)
		if err == 1:
			print "Error: Username '%s' already exists." % sys.argv[2]

	elif sys.argv[1].upper() == GET_CMD:	
		if len(sys.argv) != 3:
			printError()

		password = getCredential(sys.argv[2])
		printSuccess(sys.argv[2], password)

	else:
	 	printError()


