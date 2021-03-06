// Hash collision testing program for part 4 of Homework 5
// Robert Bell

public class HashCollision {
	
	public static void main(String args[]) {
		// Vars
		int collisionTrialsRaw = 0;
		int collisionTrialsAvg = 0;
		
		// Setup Alice Instance (Key is generated by constructor)
		Alice alice = new Alice();
		
		// Run first trial
		alice.generateHashTest(8);
		System.out.println("The original hash was " + alice.getHashTestLiteral() + ".");
		System.out.println("The original message was " + alice.getHashTestMessage() + ".");
		
		String breaker = alice.FindCollision();
		System.out.println("The breaker hash was " + breaker + ".");
		System.out.println("The breaker message was " + alice.getHashTestMessage() + ".");
		
		System.out.println("This took " + alice.getAttempts() + " trials to find.");
		
		System.out.println("-------------------- Now testing for hash collisions ------------------");
		// Iterate 20 instances of collision testing
		for (int i = 0; i < 20; i++) {
			// Run Trial
			alice.generateHashTest(8);
			alice.FindCollision();
			
			// Add attempts to raw
			collisionTrialsRaw += alice.getAttempts();
			
		}
		// Calcualte average as raw/20 to get avg
		collisionTrialsAvg = collisionTrialsRaw / 20;
		
		// Print Out
		System.out.print("The average attemtps to find a collision was: " + collisionTrialsAvg + ".");
		
	}
	
}
