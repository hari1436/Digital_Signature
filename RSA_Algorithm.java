package Digital_Signature;
//Java provides the JDK Security API that allows us to deal with digital signatures.

import java.util.*;
import java.math.BigInteger;
//import javax.xml.bind.DatatypeConverter;  
import java.security.*; 
public class Generate_Keys {
	public static final String  SIGNING_ALGORITHM = "SHA256withRSA";  
	public static final String RSA = "RSA";                            
	 
	//function generates the digital signature by using the SHA256 and assymetric RSA algorithm  
	 public static byte[] createDigitalSignature(byte[] input, PrivateKey Key) throws Exception  
	 {  
	 Signature sig = Signature.getInstance(SIGNING_ALGORITHM);  
	 sig.initSign(Key);  
	 sig.update(input);  
	 return sig.sign();  
	 } 
	 public static KeyPair generateRSAKeyPair() throws Exception  
	 {  
	 SecureRandom sr = new SecureRandom();  
	 KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);  
	 kpg.initialize(2048, sr);  
	 return kpg.generateKeyPair();  
	 }  
	//function verifies the signature by using the public key  
	 public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception  
	 {  
	 Signature sig = Signature.getInstance(SIGNING_ALGORITHM);  
	 sig.initVerify(key);  
	 sig.update(input);  
	 return sig.verify(signatureToVerify);  
	 }  
	 
	 
	 	public static void main(String[] args)throws Exception   {
		KeyPair keyPair = generateRSAKeyPair();  
		System.out.printf("Private key = %s",(keyPair.getPrivate()));
	    System.out.println();
		System.out.printf("Public key = %s",(keyPair.getPublic()));
		 System.out.println();
		Scanner sc=new Scanner(System.in);
		System.out.println("Enter the message to be signed");
		String input=sc.next();
		byte[] sig = createDigitalSignature(input.getBytes(), keyPair.getPrivate());  
		System.out.printf("Signature Value:\n " + new BigInteger(1, sig).toString(16));  
		 System.out.println();
		System.out.println("Verification: "+ verifyDigitalSignature(input.getBytes(), sig, keyPair.getPublic()));  
	}
}
