# encryptor
>  Encryptor is a command line application for file encryption using AES.
### Encrypter is a command-line application for encryption and decryption of any type of file using the AES encryption algorithm. AES is a symmetric key encryption algorithm which is next to impossible to crack if the encryption public key is not available. Encrypter provides usage of three key sizes i.e 128, 192 and 256 bits, however unless you are encrypting a military level file, key size of 128 bits is sufficient.
Encrypter uses *[argparser](https://www.cs.ubc.ca/~lloyd/java/doc/argparser/argparser/ArgParser.html)* for command line argument parsing.<br>

## How to run ?
first `cd` into the encrypter directory and follow any one method

#### 1. Using the jar file
 `
java -jar encrypter.jar
`

#### 2. Using the class file
`
java -cp ".;argparser.jar" encrypter
`

if you dont want to mess around with java classpath and including external jar files everytime you run application, then use the first method.

---

#### if you like the app give a star , if you find any bugs create a issue or PR
