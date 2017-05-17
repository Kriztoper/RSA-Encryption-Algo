package rsa.main;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class RSA {

	private static final int BIT_LENGTH = 2048;
	private String encryptedText;
	private String decryptedText;
	private String plainText;
	private String publicKeyText;
	private String privateKeyText;
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger phi;
	private BigInteger e;
	private BigInteger d;
	private BigInteger[] encryptedBigInts;
	
	public static void main(String[] args) {
		// Enter plain text
		System.out.print("Message encryption and "
				+ "decryption program "
				+ "using RSA algorithm\n"
				+ "Enter message: ");
		Scanner scanner = new Scanner(System.in);
		String input = scanner.nextLine();
		
		RSA rsa = new RSA();
		String encryptedMessage = rsa.encrypt(input);
		// print encrypted message
		System.out.println("Encrypted message: " + encryptedMessage);
		
		String decryptedMessage = rsa.decrypt();
		// print decrypted message
		System.out.println("Decrypted message: " + decryptedMessage);
	}
	
	public RSA() {
		generatePublicAndPrivateKeys();
	}
	
	private void generatePublicAndPrivateKeys() {
		Random random = new SecureRandom();

		// generate random primes p and q
		p = new BigInteger(BIT_LENGTH/2, 100, random);
		q = new BigInteger(BIT_LENGTH/2, 100, random);
		
		// n = p * q
		n = p.multiply(q);
		
		// phi = (p - 1) * (q - 1)
		phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		// 1 < e < phi
		do {
			e = new BigInteger(phi.bitLength(), random);
		} while((e.compareTo(BigInteger.ONE) <= 0) ||  // e < 1
				(e.compareTo(phi) > 0) || 			   // e > phi
				(!e.gcd(phi).equals(BigInteger.ONE))); // gcd(e, phi) == 1
		
		// d = e^-1 % phi
		d = e.modInverse(phi);
		
		// set public key as string
		publicKeyText = e.toString();
		
		// set private key as string
		privateKeyText = d.toString();
		
		System.out.println("Public key: " + publicKeyText);
		System.out.println("Private key: " + privateKeyText);
	}
	
	public String encrypt(String plainText) {
		this.plainText = plainText;

		// convert plain text to array of bytes
		byte[] bytes = plainText.getBytes();
		byte[] tempByte = new byte[1];
		BigInteger[] bigBytes = new BigInteger[bytes.length];
		
		// convert array of bytes to array of big integers
		for (int i = 0; i < bytes.length; i++) {
			tempByte[0] = bytes[i];
			bigBytes[i] = new BigInteger(tempByte);
		}
		
		// encrypt array of big integers then
		// append to cipher text
		encryptedBigInts = new BigInteger[bigBytes.length];
		encryptedText = "";
		for (int i = 0; i < bigBytes.length; i++) {
			encryptedBigInts[i] = bigBytes[i].modPow(e, n);
			encryptedText += encryptedBigInts[i].toString();
		}
		
		return encryptedText;
	}
	
	public String decrypt() {
		decryptedText = "";
		byte[] bytes = new byte[plainText.getBytes().length];
		for (int i = 0; i < encryptedBigInts.length; i++) {
			bytes[i] = encryptedBigInts[i].modPow(d, n).byteValue();
		}
		
		decryptedText = new String(bytes);
		
		return decryptedText;
	}
}
