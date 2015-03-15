# Password-Manager
Python Password Manager

<b>Basics</b>

The passwords are encrypted using AES-128, and the encryption key is derived at runtime using PBKDF2 using an entered master password and a random salt. 

<b>Security Design</b>

First, I decided to use AES-128 for the encryption. I opted out of using AES-256 and AES-192 because both use less secure key scheduling algorithms than AES-128. This means that under certain attacks, it may actually be easier to compromise keys for AES-256 or AES-192 than for AES-128. Furthermore, for the foreseeable future it will remain impractical to brute force even a 128-bit key.
PBKDF2 is used to generate encryption keys. PBKDF2 takes in a master password entered by the user that is hashed with SHA512, a randomly generated 16-byte salt, and performs 10000 iterations to compute a key of 128 bits in length. The password is hashed and a random salt is used to ensure a large amount of entropy in the PBKDF2 function. It performs 10000 iterations to make it more difficult for an attacker to brute force the key by password guessing. Also, the amount 10000 was chosen because this is the maximum amount Lastpass recommends using in their application’s PBKDF2 function that will have a negligible performance impact. Finally, the random salt is prepended to the encrypted password’s ciphertext in the file. This is so the salt can be pulled off of the ciphertext and used to generate the key for decryption. Since the salt is randomized for each password, a different encryption key is generated and used for each saved password. 

<b>General Algorithm: </b>

    passhash = hashlib.sha512(password).hexdigest()
    key = KDF.PBKDF2(passhash, salt, 16, 10000)
    ciphertext = base64.b64encode(salt + cipher.encrypt(plaintext))

The SHA512 of the user’s master password is used in another way, alongside with PBKDF2 to generate encryption keys. It is encrypted with its own encryption key, which is derived from PBKDF2, and stored in a file with its salt prepended to the ciphertext. This encrypted hash is used to check if the user has entered their master password correctly, so the user can be notified accordingly. The way this works is the master password is entered and hashed. This hash is then fed into PBKDF2 to generate an encryption key. The key is used to decrypt the encrypted SHA512 hash in the file. Then, the hash in the file is compared to the hash just generated from the entered master password. The only realistic way the two hashes will be equal is if the correct encryption key was generated from the correct password. Although it is theoretically possible to find a collision with an incorrect password, it will never cause any data discloser. The encrypted hash is present purely for the user’s convenience. The reason the SHA512 hash is encrypted is to make brute forcing the hash, on its own, to get the master password impossible.
Random text padding is added to each side of the plaintext password before applying encryption. The whole ciphertext is then stored to the password file. This technique was done to increase the number of blocks used by AES, making the ciphertext appear to be more random. When decrypting, the whole ciphertext is decrypted, and then the plaintext padding is removed from either side of the password. 

<b>Usability Design</b>

My goal with this application was not only to make it store the user’s passwords securely but also to make using the application simple and sleek. I thought the best way to do this was to allow both storing and retrieving of account passwords to be done in one-line commands. An example of both of these commands is show below, respectively. 

    python manager.py -S us3rname passw0rd –c
    python manager.py -A us3rname

The application also provides ‘fail-safe’ default options, case-insensitive flags, a formatted help menu, and a help command prompt when a malformed commend is entered. For example, if the AES mode flag is not set, the application will default to CTR mode. Another example is if the save flag (-S) or the retrieve flag (-A) is not set, then the command to show the help menu is printed. 

    [Help:] python manager.py –h
