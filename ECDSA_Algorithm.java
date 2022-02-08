package Digital_Signature;
import java.util.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec; 
public class edcsa {
	public static byte[] createDigitalSignature(byte[] input, PrivateKey Key) throws Exception  
	 {  
	 Signature sig = Signature.getInstance("SHA256withECDSA","SunEC");  
	 sig.initSign(Key);  
	 sig.update(input);  
	 return sig.sign();  
	 } 
	
	public static KeyPair generateRSAKeyPair() throws Exception  
	 {  
	 SecureRandom sr = new SecureRandom();  
	 KeyPairGenerator g= KeyPairGenerator.getInstance("EC","SunEC");  
	 ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256k1");
	 g.initialize(ecsp);
	 
	 return g.generateKeyPair();  
	 }  
	
	//function verifies the signature by using the public key  
         public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception  
		 {  
		 Signature sig = Signature.getInstance("SHA256withECDSA","SunEC");  
		 sig.initVerify(key);  
		 sig.update(input);  
		 return sig.verify(signatureToVerify);  
		 }  
	public static void main(String[] args)throws Exception {
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
