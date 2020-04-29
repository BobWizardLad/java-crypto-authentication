// Reciever Class for Homework 5
// Robert Bell Spring 2020

import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Bob {
	// Keys
	private SecretKey symKey;
	private PublicKey pubKey;
	
	// Messages
	private byte[] HMACCode = new byte[32];
	private byte[] SIGCode = new byte[256];
	private String HMACMessage;
	private byte[] SIGMessage;
	int msgLen;
	
	public Bob() {
		
	}
	
	// ----------------------------------- HMAC --------------------------------------
	
	// Retrieve Symmetric Key
	public void CollectSymKey(String filename) {
		FileInputStream in;
		byte[] key = new byte[256];
		// Open file and get key
		try {
			in = new FileInputStream(filename);
			key = Files.readAllBytes(Paths.get(filename));
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		symKey = new SecretKeySpec(key, "HMACSHA256");
	}
	
	// Retrieve Message
	public void RetrieveHMAC(String filename) {
		FileInputStream in;
		byte[] message = new byte[18];
		// Open file and retrieve message
		try {
			in = new FileInputStream(filename);
			in.read(HMACCode, 0, 32);
			//message = Files.readAllBytes(Paths.get(filename));
			in.read(message);
			msgLen = message.length;
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		HMACMessage = new String(message);
		
	}
	public void RetrieveHMAC(String filename, int length) {
		FileInputStream in;
		byte[] message = new byte[length];
		// Open file and retrieve message
		try {
			in = new FileInputStream(filename);
			in.read(HMACCode, 0, 32);
			//message = Files.readAllBytes(Paths.get(filename));
			in.read(message);
			msgLen = message.length;
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		HMACMessage = new String(message);
		
	}
	
	// Authenticate HMAC
	public boolean AuthenticateHMAC() {
		byte[] MACText = null;
		byte[] recieved = HMACMessage.getBytes();
		
		// Generate Code
		try {
			Mac mac = Mac.getInstance("HMACSHA256");
			mac.init(symKey);
			MACText = mac.doFinal(recieved);
		} catch (Exception e) {
			System.out.println("Exception at HMAC auth generation: " + e);
		}
		
		// Check Authentication
		for (int i = 0; i < msgLen; i++) {
			if (Byte.compare(HMACCode[i], MACText[i]) != 0) {
				System.out.println("The codes don't match! HMAC Rejected.");
				return false;
			}
		}
		
		System.out.println("The codes match! HMAC Accepted.");
		return true;
		
	}
	
	//--------------- RSA --------------------
	
	// Retrieve Public Key
	public void CollectAsymKey(String filename) {
		FileInputStream in;
		byte[] key = new byte[256];
		// Open file and get key
		try {
			in = new FileInputStream(filename);
			key = Files.readAllBytes(Paths.get(filename));
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		try {
			pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
		} catch (Exception e) {
			System.out.println("Exception at Key storage: " + e);
		}
	}
	
	// Retrieve SIG Message
	public void retrieveSIGMessage(String filename) {
		FileInputStream in;
		byte[] message = new byte[18];
		// Open file and retrieve message
		try {
			in = new FileInputStream(filename);
			//message = Files.readAllBytes(Paths.get(filename));
			in.read(message, 0, 18);
			in.read(SIGCode, 0, 256);
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		SIGMessage = message;
	}
	public void retrieveSIGMessage(String filename, int length) {
		FileInputStream in;
		byte[] message = new byte[length];
		// Open file and retrieve message
		try {
			in = new FileInputStream(filename);
			//message = Files.readAllBytes(Paths.get(filename));
			in.read(message, 0, length);
			in.read(SIGCode, 0, 256);
			in.close();
		} catch (Exception e) {
			System.out.println("Exception at Key retrieval: " + e);
		}
		// Assign object
		SIGMessage = message;
	}
	
	// Authenticate SIG
	//-----------------------------------------
	// Known Bug:
	//	Signature does not verify for imported Key and Signature.
	//	Possible causes would be wrong pubKey component, wrong SIGCode component,
	//	However, SIGCode and pubKey appear to match, though I suspect pubKey is the culprit.
	//	In any case, the problem lies either in the data transfer or the verification process,
	//	two library operations I need further information on (Encoding practices, library function behaviors, etc...)
	//-----------------------------------------
	public boolean AuthenticateSIG() {
		boolean solution = false;
		
		// Init Signature
		try {
			Signature privSig = Signature.getInstance("SHA256withRSA");
			privSig.initVerify(pubKey);
			privSig.update(SIGMessage);
			solution = privSig.verify(SIGCode);
		} catch (Exception e) {
			System.out.println("Exception at SIG Authentication: " + e);
		}
		
		// Check Authentication
		if (solution) {
			System.out.println("Signature verified! Signature Accepted.");
			return true;
		}
		
		System.out.println("Signature not verified! Signature Rejected.");
		return true;
	}
	
	public static void main(String args[]) {
		// Call init of Alice
		Bob bob = new Bob();
		
		// Retrieve private key
		bob.CollectSymKey("key.txt");
		
		// Recieve HMAC Message
		bob.RetrieveHMAC("mactext.txt");
		
		// Authenticate HMAC Message
		bob.AuthenticateHMAC();
		
		// Retrieve Alice Public Key
		bob.CollectAsymKey("ApubKey.txt");
		
		// Retrieve RSA SIG Message
		bob.retrieveSIGMessage("sigtext.txt");
		
		// Authenticate RSA SIG Message
		bob.AuthenticateSIG();
	}
}