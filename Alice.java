// Sender Class for Homework 5 Project
// Robert Bell Spring 2020

import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
	// Keygen
	private KeyGenerator kGen;
	private KeyPairGenerator pairGen;
	private SecretKey symKey;
	private KeyPair pair;
	
	// HashTest Message
	private byte[] hashtest;
	private byte[] hashTestMessage;
	private int attempts = 0;
	
	// Construct
	public Alice() {
		// Init kGen with SHA-256
		try {
			kGen = KeyGenerator.getInstance("HMACSHA256");
		} catch (Exception e) {
			System.out.println("Exception at Keygen init: " + e);
		}
		
		// Generate Symmetric Key
		symKey = kGen.generateKey();
		
		// Init pairGen for RSA-2048
		try {
			pairGen = KeyPairGenerator.getInstance("RSA");
			pairGen.initialize(2048, new SecureRandom());
		} catch (Exception e) {
			System.out.println("Exception at Keypair init: " + e);
		}
		
		// Generate key pair
		pair = pairGen.generateKeyPair();
		
	}
	
	// ----------------------------------- HMAC --------------------------------------
	
	// Exports The Symmetric Key to File
	public void ExportSymKey(String filename) {
		FileOutputStream out = null;
		
		// Write To File Safely
		try {
			out = new FileOutputStream(filename);
			out.write(symKey.getEncoded());
			out.close();
		} catch (Exception e) {
			System.out.println("Exception at SymKey export: " + e);
		}
	}
	
	// Sends MSG+HMAC Code to file
	public void SendHMACMessage(String filename, String message) {
		byte[] MACText = null;
		
		// Generate Code
		try {
			Mac mac = Mac.getInstance("HMACSHA256");
			mac.init(symKey);
			MACText = mac.doFinal(message.getBytes());
		} catch (Exception e) {
			System.out.println("Exception at HMAC generation: " + e);
		}
		
		// Export
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(filename);
			out.write(MACText);
			out.write(message.getBytes());
			out.close();
		} catch (Exception e) {
			System.out.println("Exception at HMAC export: " + e);
		}
	}
	
	// ---------------------- Collision Testing ---------------------------------------
	
	// Builds an HMAC message for testing
	public byte[] GenerateHash(int length) {
		hashTestMessage = GenerateByteString(128);
		byte[] MACText = null;
		byte[] firstbytes = new byte[length];
		
		// Generate Code
		try {
			Mac mac = Mac.getInstance("HMACSHA256");
			mac.init(symKey);
			MACText = mac.doFinal(hashTestMessage);
		} catch (Exception e) {
			System.out.println("Exception at HMAC generation: " + e);
		}
		
		// Get first 8 bits
		for (int i = 0; i < length; i++) {
			firstbytes[i] = MACText[i];
		}
		
		// Save first8 var for test
		return firstbytes;
		
	}
	
	// Generates random bytestring of length
	private byte[] GenerateByteString(int length) {
		SecureRandom random = new SecureRandom();
		byte[] end = new byte[length];
		random.nextBytes(end);
		
		return end;
	}
	
	// Generate Hash for testing
	public void generateHashTest(int length) {
		hashtest = GenerateHash(8);
	}
	
	// Get hashtest
	public String getHashTestLiteral() {
		return new String(hashtest);
	}
	
	// Get hashTestMessage
	public String getHashTestMessage() {
		return new String(hashTestMessage);
	}
	
	// Get attempts
	public int getAttempts() {
		return attempts;
	}
	
	// Finds a hash that collides with Alice's testHash
	public String FindCollision() {
		// Store generated hashes
		attempts = 0;
		byte[] smashHash = null;
		
		boolean badHash;
		
		// Iterate until collision is found
		do {
			// Keep iterating until true is triggered
			badHash = false;
			
			// Get new hash for smashHash
			smashHash = GenerateHash(8);
			
			// Check Hash Matching
			for (int i = 0; i < hashtest.length; i++) {
				if (Byte.compare(smashHash[i], hashtest[i]) == 0) {
					badHash = true;
				}
			}
			attempts++;
		} while (!(badHash));
		
		return new String(smashHash);
	}
	
	
	//-------------------------------- RSA --------------------------------------------------
	
	// Export public key to file
	public void ExportPublicKey(String filename) {
		FileOutputStream out = null;
		PublicKey pubComp = pair.getPublic();
		byte[] pubBytes = pubComp.getEncoded();
		
		// Write To File Safely
		try {
			out = new FileOutputStream(filename);
			out.write(pubBytes);
			out.close();
		} catch (Exception e) {
			System.out.println("Exception at AsymKey export: " + e);
		}
	}
	
	// Generate & Export sig message
	public void SendSIGMessage(String filename, String message) {
		byte[] SIGText = null;
		
		// Generate Code
		try {
			Signature privSig = Signature.getInstance("SHA256withRSA");
			privSig.initSign(pair.getPrivate());
			privSig.update(message.getBytes());
			SIGText = privSig.sign();
		} catch (Exception e) {
			System.out.println("Exception at SIG generation: " + e);
		}
		
		// Export
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(filename);
			out.write(message.getBytes());
			out.write(SIGText);
			out.close();
		} catch (Exception e) {
			System.out.println("Exception at SIG export: " + e);
		}
		
	}
	
	// ----------------------------------------------- Part 1+2 Main -----------------------------------------
	
	public static void main(String args[]) {
		Scanner input = new Scanner(System.in);
		
		// Call init of Alice
		Alice alice = new Alice();
		
		// Store private key
		System.out.println("Exporting the private key to Bob...");
		alice.ExportSymKey("key.txt");
		
		// Generate & send HMAC
		System.out.println("Input HMAC message...");
		String message = input.nextLine();
		System.out.println("Sending signature text To Bob...");
		alice.SendHMACMessage("mactext.txt", message);
		
		// Send PubKey
		System.out.println("Exporting my public key to Bob...");
		alice.ExportPublicKey("APubKey.txt");
		
		// Generate & send Sig
		System.out.println("Input Signature message...");
		message = input.nextLine();
		System.out.println("Sending signature text To Bob...");
		alice.SendSIGMessage("sigtext.txt", message);
		
		System.out.println("Done!");
	}
	
}
