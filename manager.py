from crypto import CCrypto  #my crypto class
from Crypto import Random   #pycryto class (Case is important!!)
import sys, os
import getpass
import hashlib

#GLOBALS
gHELP_CMD = '-h'
gSAVE_CMD = '-S'
gGET_CMD = '-A'

gCBC_MODE = '-c'
gCTR_MODE = '-r'
gEBC_MODE = '-e'

gCHECK_FILE_NAME = 'checkfile.txt'
gCREDS_FILE_NAME = 'passwd.txt'


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
	print "[Example:] python %s %s us3rname passw0rd -c" % (sys.argv[0], gSAVE_CMD)
	print "\n[Retrieving:] python %s <method> <username>" % sys.argv[0]
	print "[Example:] python %s %s us3rname" % (sys.argv[0], gGET_CMD)
	print "\nMethods: "
	print "%s  -  Save a username and password" % gSAVE_CMD
	print "%s  -  Retrieve a password by username" % gGET_CMD
	print "No default method. One of the above methods must be selected."
	print "\nOptions (AES Mode):"
	print "-e  -  EBC Mode (Insecure)"
	print "-r  -  CTR Mode (Recommended, Default)"
	print "-c  -  CBC Mode"
	print "\nMaster Password: "
	print "- You will be prompted to enter a master password to generate your AES key."
	print "- The master password is set the first time the program is run."
	print "- The same master password must then be used for future encryption/decryption.\n"
	sys.exit(1)


#-------- USER CREDENTIAL FUCNTIONS --------#
def padPassword(password):  
	size = 0x10  # 16 bytes - pads each side with one AES block
	frontStr = Random.new().read(size).encode('hex')
	backStr = Random.new().read(size).encode('hex')
	padded = frontStr + password + backStr
	return padded


def unpadPassword(password):
	size = 0x10 * 2  # must double the size as padPassword()
	unpaded = password[size:-size]
	return unpaded


def getMasterPassword():
	password = getpass.getpass("Password:") #hidden input
	passhash = hashlib.sha512(password).hexdigest() #sha512 is more difficult for GPUs
													#also more blocks for encryption
	if not os.path.isfile(gCHECK_FILE_NAME):
		repassword = getpass.getpass("Reenter Password:") 
		if password != repassword:
			print "Error: Passwords do not match!"
			sys.exit(1)

		ofl = open(gCHECK_FILE_NAME, 'w') #create file but dont do anything
		ofl.close()

	return passhash  # hash is more secure than the plaintext password


def checkMasterPassword(pwdhash):
	filesize = os.stat(gCHECK_FILE_NAME).st_size
	retval = 0
	cc_cbc = CCrypto("c")
	cc_cbc.setPassword(pwdhash)

	if filesize == 0: #Master Password just created
		crypthash = cc_cbc.encrypt(pwdhash)
		ofl = open(gCHECK_FILE_NAME, 'w')
		ofl.write(crypthash)
		ofl.close()
		if os.path.isfile(gCREDS_FILE_NAME):
			os.remove(gCREDS_FILE_NAME) #remove credentials under different key
	else:
		ifl = open(gCHECK_FILE_NAME, 'r')
		line = ifl.readline().rstrip('\n')
		ifl.close()	
		filehash = cc_cbc.decrypt(line)

		if filehash == pwdhash:
			retval = 0
		else:
			retval = 1

	return retval


def saveCredentials(username, password, option='-c'):
 	option = option[1:].lower()   #blank option wont cause a problem
	if len(option) != 1:
		printError()
	
	try:
		with open(gCREDS_FILE_NAME) as ifl:
			for line in ifl:
				line = line.rstrip('\n')
				(uname, cipher, opt) = line.split('|')
				if uname == username:
					return 1
	except:
		pass

	cc = CCrypto(option)
	masterpass = getMasterPassword() #returns sha512 hash of password
	cc.setPassword(masterpass)
	
	if checkMasterPassword(masterpass) > 0:
		return 2

	paddedPassword = padPassword(password) #pad password for more encryption blocks
	filestr = username + '|' + cc.encrypt(paddedPassword) + '|' + option + '\n'

	ofl = open(gCREDS_FILE_NAME, 'a')
	ofl.write(filestr)
	ofl.close()


def getCredential(username):
	nameNotFound = True
	try:
		with open(gCREDS_FILE_NAME) as ifl:
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

	if checkMasterPassword(masterpass) > 0:
		print "Error: Incorrect master password entered. Try again."
		sys.exit(1)

	password = unpadPassword(cc.decrypt(cipher))
	return password


#------- MAIN --------#
if __name__ == '__main__':
	if len(sys.argv) < 2 or len(sys.argv) > 5:
		printError()

	if sys.argv[1][:2].lower() == gHELP_CMD:
		printHelp()

	elif sys.argv[1].upper() == gSAVE_CMD:
		opt = gCTR_MODE  # defualt mode is CTR
		if len(sys.argv) < 4 or len(sys.argv) > 5:
			printError()
		elif len(sys.argv) == 5:
			opt = sys.argv[4]
			if opt != gCBC_MODE and opt != gCTR_MODE and opt != gEBC_MODE:
				print "Error: '%s' is not a valid encryption option." % opt
				printError()

		err = saveCredentials(sys.argv[2], sys.argv[3], opt)
		if err == 1:
			print "Error: Username '%s' already exists." % sys.argv[2]
		elif err == 2:
			print "Error: An incorrect master password was entered."

	elif sys.argv[1].upper() == gGET_CMD:	
		if len(sys.argv) != 3:
			printError()

		password = getCredential(sys.argv[2])
		printSuccess(sys.argv[2], password)

	else:
	 	printError()


