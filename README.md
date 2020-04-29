# Java_Crypto_Authentiation
System using Java.crypto to generate, send, recieve, and verify private and public key authentication sent via text file i/o 
using SHA-265 Hash and RSA Digital Signature.

Also tests efficency of each method and tests hash collision on SHA-256

From university project on the subject

-- Procedure --

Alice.java simulates the sender who generates keys and creates the initial Hash/Signature.
Bob.java simulates the reciever, and verifies the Hash/Signature sent.
Testing.java inherits from Alice and Bob, and uses their functions (Alice and Bob are classes) to test the speed of each method
HashCollision.java performs hash collision testing on the first 8-bits of an SHA-256 Hash to test how many randomly generated hashes must be created before a collision occours.
