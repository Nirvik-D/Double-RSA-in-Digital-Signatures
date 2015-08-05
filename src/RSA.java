import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
  
  
public class RSA {  
    
	final static long startTime = System.currentTimeMillis();
    private BigInteger p;  
    private BigInteger q;  
    private BigInteger N;  
    private BigInteger phi;  
    private BigInteger pub_key;  
    private BigInteger pri_key;  
    private int bitlength = 1024;  
    private int blocksize = 256; //blocksize in byte  
    static String symmetric_key, concatenate, encrypted_msg, digital_signature, senders_package, MD5hash_msg, MD5hash_key;
    static String recv_MD5hash_key, decrypting_sym_key;
    static String algorithm = "AES";
    private Random r;  
    public RSA() {  
        r = new Random();  
        //System.out.print("val"+r);
        p = BigInteger.probablePrime(bitlength, r); 
        //System.out.print("val"+p);
        q = BigInteger.probablePrime(bitlength, r);
        //System.out.print("val"+q);
          N = p.multiply(q);  
            
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));  
        pub_key = BigInteger.probablePrime(bitlength/2, r);  
          
        while (phi.gcd(pub_key).compareTo(BigInteger.ONE) > 0 && pub_key.compareTo(phi) < 0 ) {  
        	pub_key.add(BigInteger.ONE);  
        }  
 pri_key = pub_key.modInverse(phi);   
    }  
      
    public RSA(BigInteger symmetric_key, BigInteger d, BigInteger N) {  
        this.pub_key = symmetric_key;  
        this.pri_key = d;  
        this.N = N;  
    }  
    
    public static void main (String[] args) throws IOException, Exception{
  
    	Key symKey = KeyGenerator.getInstance(algorithm).generateKey();
    	Cipher c = Cipher.getInstance(algorithm);
        RSA rsa = new RSA();  
        //DataInputStream in=new DataInputStream(System.in);   
        String teststring ;
        teststring = readFile("X:/Hello.txt",Charset.defaultCharset());
        System.out.println("Encrypting File Hello.....");
        //System.out.println("Encrypting String: " + teststring);  
        //System.out.print9ln("String in Bytes: " + bytesToString(teststring.getBytes()));  
  
        // encrypt using Symmetric key
        byte[] encrypted = encryptFunc(teststring,symKey,c);

        // encrypt Symmetric Key using public Key
        symmetric_key = symKey.toString();
        System.out.println("Encrypting symmetric key: " + symmetric_key);  
        System.out.println("Public Key in Bytes: " + bytesToString(symmetric_key.getBytes())); 
        byte[] encrypted_sym_key = rsa.encrypt(symmetric_key.getBytes());                    
        System.out.println("Encrypted String in Bytes: " + bytesToString(encrypted_sym_key));
        
        //Message digest of Message and Symmetric key
        MD5hash_msg = RSA.getMD5(teststring);
        //System.out.println(MD5hash_msg);
        MD5hash_key = RSA.getMD5(symmetric_key);
        //System.out.println(MD5hash_key);
        
        //concatenate strings 
        concatenate = encrypted_sym_key + "_" + MD5hash_msg + "_" + MD5hash_key;
        
        //Signing with Digital signature
        System.out.println("Encrypting Concatenated: " + concatenate);  
        System.out.println("Concatenated in Bytes: " + bytesToString(concatenate.getBytes())); 
        byte[] digital_signature_ = rsa.digital_signature(concatenate.getBytes());                    
        System.out.println("Digital Signature in Bytes: " + bytesToString(digital_signature_));
        
        byte[] digital_Signature_encryption = rsa.encrypt(bytesToString(digital_signature_).getBytes());                    
        System.out.println("Encrypted Digital Signature in Bytes: " + bytesToString(digital_Signature_encryption));
        
        //Concatenate Signature with encrypted message
        String encrypted_msg = new String(encrypted);
        String encrypted_digi_sig = new String(digital_Signature_encryption);
        String con_digi_rsa = encrypted_msg + encrypted_digi_sig;
        
        //Implementing double RSA
        System.out.println("Encrypting Concatenated Array: " + con_digi_rsa);  
        System.out.println("Concatenated in Bytes: " + bytesToString(con_digi_rsa.getBytes())); 
        byte[] encrypted_concatenated_array = rsa.encrypt(con_digi_rsa.getBytes());                    
        System.out.println("Encrypted Concatenated array in Bytes: " + bytesToString(encrypted_concatenated_array)); 
        
//---------------------------------------------------------------Message gets sent----------------------------------------------------------//
      
        // decrypt concatenated
        //byte[] decrypted_concatenation = rsa.decrypt(encrypted_concatenated_array);        
        //System.out.println("Decrypted concatenated array in Bytes: " +  bytesToString(decrypted_digital_signature));     
        //System.out.println("Decrypted concatenated array: " + new String(decrypted_digital_signature));
        
        byte[] digital_signature_decryption = rsa.decrypt(digital_Signature_encryption);
        System.out.println("Decrypted Digital Signature in Bytes: " +  bytesToString(digital_signature_decryption));
       
        // decrypt concatenated
        byte[] d_digital_signature = rsa._digital_signature(digital_signature_);        
        System.out.println("Digital Signature in Bytes: " +  bytesToString(d_digital_signature));  
          
        System.out.println("Digital Signature: " + new String(d_digital_signature));
        
        // decrypt symmetric key and validate
        byte[] decrypted_sym_key = rsa.decrypt(encrypted_sym_key);        
        System.out.println("Decrypted Symmetric key in Bytes: " +  bytesToString(decrypted_sym_key));  
          
        System.out.println("Decrypted Symmetric Key: " + new String(decrypted_sym_key));
        
        decrypting_sym_key = new String(decrypted_sym_key);
        recv_MD5hash_key = RSA.getMD5(decrypting_sym_key);
        //System.out.println(recv_MD5hash_key);
        
        if(recv_MD5hash_key.equals(MD5hash_key)){
        	System.out.println("Valid Symmetric Key");
        }
        else{
        	System.out.println("Invalid Symmetric Key");
        }
        
        // decrypt message  
        String decrypted = decryptFunc(encrypted,symKey,c);
        File file = new File("X:/Encrypted_Hello.txt");
        file.createNewFile();
        PrintWriter out = new PrintWriter("X:/Encrypted_Hello.txt");
        out.println(decrypted);
        out.close();
        //System.out.println("Decrypted: " + decrypted);
        
        String recv_MD5hash_msg = RSA.getMD5(decrypted);
        //System.out.println(recv_MD5hash_msg);
        
        if(recv_MD5hash_msg.equals(MD5hash_msg)){
        	System.out.println("Valid Message");
        }
        else{
        	System.out.println("Invalid Message");
        }
         
        final long endTime = System.currentTimeMillis();
        final long interval = endTime - startTime;
        System.out.println("Total execution time: " + interval + " milliseconds" );
        File file1 = new File("X:/Timing_Records_txt_RSA.txt");
        file1.createNewFile();
        String filename= "X:/Timing_Records_txt_RSA.txt";
        FileWriter fw = new FileWriter(filename,true); //the true will append the new data
        fw.write(" " + interval + " ms, ");//appends the string to the file
        fw.close();
          
    }  
    
//-------------------------------------------------------------------------------------------//
    private static byte[] encryptFunc(String input,Key pkey,Cipher c) throws InvalidKeyException, BadPaddingException,IllegalBlockSizeException {
    	c.init(Cipher.ENCRYPT_MODE, pkey);
    	  byte[] inputBytes = input.getBytes();
    	  return c.doFinal(inputBytes);
    }
    
    private static String decryptFunc(byte[] encryptionBytes,Key pkey,Cipher c) throws InvalidKeyException,BadPaddingException, IllegalBlockSizeException {
    	  c.init(Cipher.DECRYPT_MODE, pkey);
    	  byte[] decrypt = c.doFinal(encryptionBytes);
    	  String decrypted = new String(decrypt);
    	  return decrypted;
    }    
    
    private static String bytesToString(byte[] encrypted) {  
        String test = "";  
        for (byte b : encrypted) {  
            test += Byte.toString(b);  
        }  
        return test;  
    }
    
    public byte[] digital_signature(byte[] hash) {       
        return (new BigInteger(hash)).modPow(pri_key, N).toByteArray();  
    }
    public byte[] _digital_signature(byte[] message) {       
        return (new BigInteger(message)).modPow(pub_key, N).toByteArray();  
    } 
    
    public byte[] encrypt(byte[] message) {       
        return (new BigInteger(message)).modPow(pub_key, N).toByteArray();  
    }  
     
    public byte[] decrypt(byte[] message) {  
        return (new BigInteger(message)).modPow(pri_key, N).toByteArray();  
    }

	//---------------------------------------------------------------------------//
	public static String getMD5(String input) {
	    try {
	        MessageDigest md = MessageDigest.getInstance("MD5");
	        byte[] messageDigest = md.digest(input.getBytes());
	        BigInteger number = new BigInteger(1, messageDigest);
	        String hashtext = number.toString(16);
	        
	        while (hashtext.length() < 32) {
	            hashtext = "0" + hashtext;
	        }
	        return hashtext;
	    }
	    catch (NoSuchAlgorithmException e) {
	        throw new RuntimeException(e);
	    }
	}  
	static String readFile(String path, Charset encoding)throws IOException 
		{
			byte[] encoded = Files.readAllBytes(Paths.get(path));
			return encoding.decode(ByteBuffer.wrap(encoded)).toString();
		}   
   
}