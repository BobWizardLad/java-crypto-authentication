import java.util.Scanner;

// Testing class for part 3 of Homework 5
// Robert Bell Spring 2020

public class Testing {
	
	public static void main(String args[]) {
		// Instantiate elements
		Alice alice = new Alice();
		Bob bob = new Bob();
		
		// Timing Elements
		double HMACTimeRaw = 0.0;
		double HMACTimeAvg = 0.0;
		double SIGGenRaw = 0.0;
		double SIGGenAvg = 0.0;
		double SIGTimeRaw = 0.0;
		double SIGTimeAvg = 0.0;
		double timeGet = 0.0;
		
		// get Message
		Scanner input = new Scanner(System.in);
		
		System.out.println("Input a 7 byte message...");
		String message = input.nextLine();
		
		
		// Implement SHA-256 HMAC in Alice/Bob
		alice.ExportSymKey("key.txt");
		bob.CollectSymKey("key.txt");
		
		// Run this exchange 100 times
		// Using message from commandline
		for (int i = 0; i < 100; i++) {
			timeGet = System.currentTimeMillis();
			alice.SendHMACMessage("mactext.txt", message);
			bob.RetrieveHMAC("mactext.txt", message.length());
			bob.AuthenticateHMAC();
			HMACTimeRaw += System.currentTimeMillis() - timeGet;
		}
		HMACTimeAvg = HMACTimeRaw / 100.0;
		
		// Implement SHA-256 HMAC in Alice/Bob
		alice.ExportPublicKey("ApubKey.txt");
		bob.CollectAsymKey("ApubKey.txt");
		
		// Run this exchange 100 times
		// Using message from commandline
		for (int i = 0; i < 100; i++) {
			timeGet = System.currentTimeMillis();
			alice.SendSIGMessage("sigtext.txt", message);
			SIGGenRaw += System.currentTimeMillis() - timeGet;
			bob.retrieveSIGMessage("sigtext.txt", message.length());
			bob.AuthenticateSIG();
			SIGTimeRaw += System.currentTimeMillis() - timeGet;
		}
		SIGTimeAvg = SIGTimeRaw / 100.0;
		SIGGenAvg = SIGGenRaw / 100.0;
		
		System.out.println("The average time fo HMAC is: " + HMACTimeAvg + "ms");
		System.out.println("The average time fo Signature Generation is: " + SIGGenAvg + "ms");
		System.out.println("The average time fo Signature Verification is: " + SIGTimeAvg + "ms");
	}
}
