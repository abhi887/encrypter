/*
	Encrypter --
	Encrypter is a small command-line application for encryption and decryption of any type of file using the AES encryption algorithm.
	AES is a symmetric key encryption algorithm which is next to impossible to crack if the encryption public key is not available.
	Encrypter provides three key sizes i.e 128, 192 and 256 bits, however unless you are encrypting a military level file, key size of 
	128 bits is sufficient.
	Encrypter uses argparser.jar for command line argument parsing.

	Citations --	
	argparser.jar - https://www.cs.ubc.ca/~lloyd/java/doc/argparser/argparser/ArgParser.html
	AES encryption - https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

	Author --
	Abhishek Vyas
*/

import java.util.Scanner;
import java.util.Base64;
import java.util.List;
import java.util.Arrays;
import java.io.File;
import java.io.FilenameFilter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import argparser.ArgParser;
import argparser.StringHolder;
import argparser.IntHolder;
import argparser.BooleanHolder;

public class encrypter{
	
	// Getting all the class files from current directory
	static String currentPath=System.getProperty("user.dir");
	static File files=new File(currentPath);
	static File fileList[]=files.listFiles();
	// some misc default values and required argument wrapper objects
	static String keyFileName="secret.key";
	static String thisFileName="encrypter";
	static final StringHolder argMode = new StringHolder();
	static final StringHolder argPath = new StringHolder();
	// optional args wrapper objects initialization with default values
	static final StringHolder argKeyPath = new StringHolder();
	static final BooleanHolder argPerformAll = new BooleanHolder(false);
	static final IntHolder argKeySize = new IntHolder(0);
	// more misc
	static SecretKey publicKey;
	static ArgParser parser = new ArgParser("encrypter -m [e/d]  -f [file/folder_path]");
	static final String argsErrorMsg="Missing required arguments :  -m [e/d]  -f [file/folder_path]";


	public static void main(String arg[]) throws Exception{
		// required args
		parser.addOption("-m, -mode %s {e,d} #Encryption/Decryption operation to perform\n",argMode);
		parser.addOption("-f, -path %s #File/Folder path to encrypt/decrypt\n",argPath);
		// optional args
		parser.addOption("-s, -keysize %d {1,2,3} #Public-Key size to use 1=128, 2=192 , 3=256 bits\n",argKeySize);
		parser.addOption("-k, -keypath %s #Path of the public key (.key file) used for previous encryption. \n\t\t\tThis argument is optional and required in decryption mode , \n\t\t\tif not provided encrypter will search for public key in the provided path\n",argKeyPath);

		parser.matchAllArgs(arg,0,parser.EXIT_ON_UNMATCHED);
		parser.matchAllArgs(arg,0,parser.EXIT_ON_ERROR);

		if(arg.length<=2) parser.printErrorAndExit(argsErrorMsg);
		else{
			try{
				if(!Arrays.asList(arg).contains("-m") || !Arrays.asList(arg).contains("-f")) parser.printErrorAndExit(argsErrorMsg);
			}
			catch(ArrayIndexOutOfBoundsException e)
			{parser.printErrorAndExit(argsErrorMsg);}
		}

		File files=new File(argPath.value);
		try{
			if(files.isDirectory()) controller(argMode.value,"directory",argPath.value,argKeyPath.value,argKeySize.value,argPerformAll.value);
			else controller(argMode.value,"file",argPath.value,argKeyPath.value,argKeySize.value,argPerformAll.value);
		}
		catch(Exception e){
			System.out.println("\n================== Decryption Failed ==================");
			System.out.println(e);
			System.out.println("========================= XXX =========================");
		}
	}


	public static void controller(String mode,String pathType,String path,String keyPath,int keysize,boolean all) throws Exception{
		switch(mode){
			case "e":
				encrypt(path,pathType,keyPath);
				break;
			case "d":
				decrypt(path,pathType,keyPath);
				break;
			default:
				throw new IllegalArgumentException();
		}
	}


	public static void encrypt(String path,String pathType,String keyPath) throws Exception{
		System.out.println("\nEncrypting ...");
		
		// Encryption object initilization section  
		Signature sign=Signature.getInstance("SHA256withRSA");
		
		// KeyPairGenerator keyPairGen=KeyPairGenerator.getInstance("RSA");
		// Cipher cipher=Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if(keyPath!=null){
			if(!directoryHasKey(keyPath)){
				System.out.println("[X] Error !\n    no public key is found at given directory !\n    please make sure public key used for encryption is present in given location\n    or use option '-k' to give location of public key at another location");
				System.exit(1);
			}
			else publicKey=getPublicKey(keyPath,"e",argKeySize.value);
		}
		else{
			publicKey=getPublicKey(argPath.value,"e",argKeySize.value);
		}

		Cipher cipher=Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE,publicKey);
		
		if(pathType.equals("directory")){
			File files=new File(path);
			File fileList[]=files.listFiles();
			
			// Writting Encrypted data to all files
			for(File tmpFile : fileList){
				if( !tmpFile.getName().equals(thisFileName+".java") && !tmpFile.getName().equals(thisFileName+".class") && !tmpFile.getName().equals(keyFileName))
				{ 
					System.out.printf("[*]  %s\n",tmpFile.getName());
					String filePath=tmpFile.getAbsolutePath();
					byte[] byteFileData=Files.readAllBytes(Paths.get(filePath));
					byte[] encryptedData=cipher.doFinal(byteFileData);
					Files.write(Paths.get(filePath),encryptedData);
				}
			}
		}
		else{
			File tmpFile = new File(path);
			System.out.printf("[*]  %s\n",tmpFile.getName());
			String filePath=tmpFile.getAbsolutePath();
			byte[] byteFileData=Files.readAllBytes(Paths.get(filePath));
			byte[] encryptedData=cipher.doFinal(byteFileData);
			Files.write(Paths.get(filePath),encryptedData);
		}

		
		// storing public Key for decryption
		String plainKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println("\n===============================================");
		System.out.printf("Encryption public key => %s\nPublic key location   => %s",plainKey,argPath.value+"\\secret.key");
		System.out.println("\n===============================================");
		// Files.write(Paths.get(currentPath + "\\" + keyFileName),publicKey.getEncoded());
	}


	public static void decrypt(String path,String pathType,String keyPath) throws Exception {
		System.out.println("\nDecrypting ...");

		SecretKey originalKey;
		if(keyPath!=null && !keyPath.equals("")){
			if(!directoryHasKey(keyPath)) throw new IllegalArgumentException();
			else originalKey=getPublicKey(keyPath,"d",0);
		}
		else{
			originalKey=getPublicKey(argPath.value,"d",0);
		}

		// SecretKey originalKey=getPublicKey(argPath.value,"d",1);
		Cipher cipher=Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE,originalKey);


		if(pathType.equals("directory")){
			File files=new File(path);
			File fileList[]=files.listFiles();
			
			// Decrypt the data and rewrite to the files
			for(File tmpFile : fileList){
				if( !tmpFile.getName().equals(thisFileName+".java") && !tmpFile.getName().equals(thisFileName+".class") && !tmpFile.getName().equals(keyFileName))
				{ 
					System.out.printf("[O]  %s\n",tmpFile.getName());
					String filePath=tmpFile.getAbsolutePath();
					Path path1 = Paths.get(tmpFile.getAbsolutePath());
					byte[] byteFileData = Files.readAllBytes(path1);
					byte[] decryptedData=cipher.doFinal(byteFileData);
					Files.write(Paths.get(filePath),decryptedData);
				}
			}
		}
		else{
			File tmpFile = new File(path);
			System.out.printf("[O]  %s\n",tmpFile.getName());
			String filePath=tmpFile.getAbsolutePath();
			Path path1 = Paths.get(tmpFile.getAbsolutePath());
			byte[] byteFileData = Files.readAllBytes(path1);
			byte[] decryptedData=cipher.doFinal(byteFileData);
			Files.write(Paths.get(filePath),decryptedData);
		}
	}


	public static SecretKey getPublicKey(String filePath,String mode,int keyBits) throws Exception{
		SecretKey key=publicKey;
		File file = new File(filePath);
		File directory;
		if(file.isDirectory()) directory = new File(filePath);
		else directory = new File(file.getParent());

		if(directoryHasKey(filePath)){
			/* use if the public key is not stored as base64 encoded string
			byte[] decodedKey = Files.readAllBytes(Paths.get(currentPath + "\\" + keyFileName ));
			byte[] decodedKey = decodedKey1.toString().getBytes("UTF-8");
			*/

			// fetching stored public key from the file
			List<String> decodedKey1 = Files.readAllLines(Paths.get(directory + "\\" + keyFileName ));
			System.out.println("[#] Using Public key  => "+decodedKey1.get(0).toString());
			byte[] decodedKey = Base64.getDecoder().decode(decodedKey1.get(0).toString());
			
			// rebuild key using SecretKeySpec
			SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
			key = originalKey;
		
			// if there is a key in the given directory and no key size is specified using "-s" option then set the key-size to size of this key encoded as [1,2,3].
			if( mode.equals("e") && keyBits==0) keyBits = (key.getEncoded().length/8)-1;
		}

		try{
			if( (!directoryHasKey(filePath) && mode.equals("e")) || ( mode.equals("e") && ( key.getEncoded().length != (64+(64*keyBits))/8 )) || (!directoryHasKey(filePath) && ( key.getEncoded().length != (64+(64*keyBits))/8 ) ) ){
				KeyGenerator keyPairGen=KeyGenerator.getInstance("AES");
				if(directoryHasKey(filePath)){
					System.out.print("[X] WARNING !\n    a key is already present in given directory\n    if you continue this action, that key will be overwritten and\n    files encrypted using that key will be lost forever.\n    Continue ?[y/n] : ");
					Scanner input = new Scanner(System.in);
					if(!input.next().equalsIgnoreCase("y")){
						System.exit(1);
					}
					input.close();
				}
				switch(keyBits){
					case 1:
						keyPairGen.init(128);
						System.out.println("[!] Using 128 bit key");
						break;
					case 2:
						keyPairGen.init(192);
						System.out.println("[!] Using 192 bit key");
						break;
					case 3:
						keyPairGen.init(256);
						System.out.println("[!] Using 256 bit key");
						break;
				}
				// SecretKey publicKey=keyPairGen.generateKey();
				publicKey=keyPairGen.generateKey();
				// PublicKey publicKey=pair.getPublic();
				String plainKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
				Files.write(Paths.get(directory + "\\" + keyFileName),plainKey.getBytes());
				key=publicKey;
			}
		}
		catch(NullPointerException e){
			System.out.println("[X] Error !\n    no public key is found at given directory !\n    please make sure public key used for encryption is present in given location\n    or use option '-k' to give location of public key at another location");
			System.exit(1);
		}
		return key;
	}


	public static boolean directoryHasKey(String filePath){
		File file = new File(filePath);
		File directory;
		if(file.isDirectory()) directory = new File(filePath);
		else directory = new File(file.getParent());
		File fileList[]=directory.listFiles(new FilenameFilter() {
			//apply a filter
			@Override
			public boolean accept(File dir, String name) {
			    	boolean result = name.endsWith(".key") ? true : false;
					return result;
				}
		});

		if(fileList.length>0) return true;
		else return false;
	}

}