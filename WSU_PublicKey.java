/**
 * @author Jenis Modi
 */
package wsu.cs527.project2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Random;

public class WSU_PublicKey {
	private final static int blockSize = 32;
	private final static int certainty = 20;

	private static void random_Integer() {
		Random randomNo = new Random(20);
		int rndno = Math.abs(randomNo.nextInt());
		System.out.println(rndno);
	}

	private static BigInteger[] wsu_Encryption(String PLAIN_TEXT, BigInteger g,
			BigInteger p, BigInteger e2) {
		System.out.println("**********************");
		System.out.println("WSU_ENCRYPTION");
		System.out.println("**********************");
		String binaryPlnTxt = AsciiToBinary(PLAIN_TEXT);
		System.out.println("Binary PlainText:" + binaryPlnTxt);
		System.out.println("Binary PlainText Length:" + binaryPlnTxt.length());
		for(int i=0;i<32;i++){
			if(binaryPlnTxt.length()!=32){
				binaryPlnTxt = binaryPlnTxt.concat("0");	
			}	
		}
		System.out.println("New Binary PlainText:" + binaryPlnTxt);
		/**
		 * Choose random value k from {0,....,p-1}
		 */
		BigInteger k = randomValue(BigInteger.ZERO, p.subtract(BigInteger.ONE));
		System.out.println(k);
		/**
		 * C1 = g^k mod p
		 */
		BigInteger C1 = g.modPow(k, p);
		/**
		 * C2 = e2^k * messageBlock mod p According to Number Theory, This is
		 * equivalent to C2 = [(e2^k mod p) * (messageBlock mod p)] mod p
		 */
		
		int decValue = Integer.parseInt(binaryPlnTxt,2);
		String strDecValue = Integer.toString(decValue);
		System.out.println("Input Decimal Value: "+decValue);
		
		BigInteger C2 = ((e2.modPow(k, p)).multiply((new BigInteger(
				strDecValue)).modPow(BigInteger.ONE, p))).mod(p);
		System.out.println("C1:" + C1);
		System.out.println("C2:" + C2);

		BigInteger CipherText[] = new BigInteger[2];
		CipherText[0] = C1;
		CipherText[1] = C2;
		return CipherText;
	}

	private static void wsu_Decryption(BigInteger C1, BigInteger C2,
			BigInteger p, BigInteger d) {
		System.out.println("########################");
		System.out.println("WSU Decryption");
		System.out.println("########################");
		/**
		 * (C1^d)^-1 * C2 mod p = Plain_Text C1 ^ (p-1-d) * C2 mod p =
		 * Plain_Text ((C1^(p-1-d) mod p) * (C2 mod p)) mod p = Plain_Text
		 */

		BigInteger p1d = p.subtract(BigInteger.ONE).subtract(d);
		BigInteger plainText = ((C1.modPow(p1d, p)).multiply((C2.modPow(
				BigInteger.ONE, p)))).mod(p);
		Long Plain_Text = plainText.longValue();
		
		String binPlainText = Long.toBinaryString(Plain_Text);
		if(binPlainText.length()!=32){
			binPlainText = "0".concat(binPlainText);
		}
		
		System.out.println("Plain text:"+Plain_Text);
		System.out.println("Binary Plain text:"+binPlainText);
		System.out.println("Binary text length:"+binPlainText.length());
	}

	/**
	 * Generate Safe Prime Java 6 Library for Miller-Rabin algorithm
	 * 
	 * @return SafePrime
	 */
	private static BigInteger genSafePrime(BigInteger generator) {

		BigInteger primeNumber = new BigInteger("0");
		BigInteger randomNo;
		BigInteger modNumber = new BigInteger("12");
		BigInteger modEqual = new BigInteger("5");
		do {
			Random random = new Random();
			do {
				randomNo = new BigInteger(32, random);
			} while (!(randomNo.isProbablePrime(certainty) && (randomNo
					.mod(modNumber).equals(modEqual))));

			primeNumber = (generator.multiply(randomNo))
					.add(new BigInteger("1"));
		} while (!(primeNumber.isProbablePrime(certainty) && primeNumber
				.bitLength() > blockSize));
		System.out.println("RandomNo:" + randomNo);
		return primeNumber;
	}

	public static BigInteger randomValue(BigInteger lowLimit,
			BigInteger highLimit) {
		Random randomNo = new Random();
		if (highLimit.compareTo(lowLimit) < 0) {
			/**
			 * Swap lowLimit and highLimit using tempLimit variable
			 */
			BigInteger tempLimit = lowLimit;
			lowLimit = highLimit;
			highLimit = tempLimit;
		} else if (highLimit.compareTo(lowLimit) == 0) {
			return lowLimit;
		}
		highLimit = highLimit.add(new BigInteger("1"));
		BigInteger difference = highLimit.subtract(lowLimit);
		int bitLength = difference.bitLength();
		BigInteger randomNumber = new BigInteger(bitLength, randomNo);
		while (randomNumber.compareTo(difference) >= 0) {
			randomNumber = new BigInteger(bitLength, randomNo);
		}
		randomNumber = randomNumber.add(lowLimit);
		return randomNumber;
	}

	private static BigInteger[] setUpKeyGen() {

		BigInteger g = new BigInteger("2");
		BigInteger p = genSafePrime(g);
		BigInteger d = randomValue(BigInteger.ONE, p);
		BigInteger e2 = g.modPow(d, p);

		BigInteger keyElements[] = new BigInteger[4];
		keyElements[0] = g;
		keyElements[1] = p;
		keyElements[2] = d;
		keyElements[3] = e2;

		File pubFile = new File("pubkey.txt");
		File priFile = new File("prikey.txt");

		try {
			if (!pubFile.exists())
				pubFile.createNewFile();

			if (!priFile.exists())
				priFile.createNewFile();

			FileWriter pubKeyFile = new FileWriter(pubFile.getName());
			FileWriter priKeyFile = new FileWriter(priFile.getName());

			BufferedWriter pubContents = new BufferedWriter(pubKeyFile);
			pubContents.write(p.toString() + " " + g.toString() + " "
					+ e2.toString());
			pubContents.close();

			BufferedWriter priContents = new BufferedWriter(priKeyFile);
			priContents.write(p.toString() + " " + g.toString() + " "
					+ d.toString());
			priContents.close();

			System.out.println("**************************");
			System.out.println("G's Value:" + g);
			System.out.println("P's Value:" + p);
			System.out.println("Is P prime? :" + p.isProbablePrime(certainty));
			System.out.println("P's Length:" + p.bitLength());
			System.out.println("d' Value:" + d);
			System.out.println("e2's Value:" + e2);
			System.out.println("**************************");

		} catch (IOException e) {
			e.printStackTrace();
		}
		return keyElements;

	}

	public static String[] READ_FILES(String fileName) {
		String s[] = null;
		try {

			FileInputStream plainTextFile = new FileInputStream(fileName);
			DataInputStream in1 = new DataInputStream(plainTextFile);
			BufferedReader br1 = new BufferedReader(new InputStreamReader(in1));
			String strLine1;
			StringBuilder sb1 = new StringBuilder();

			while ((strLine1 = br1.readLine()) != null) {
				sb1.append(strLine1);
			}

			s = new String[2];
			s[0] = sb1.toString();

			in1.close();

		} catch (Exception e) {// Catch exception if any
			System.err.println("Error: " + e);
		}
		return s;

	}

	public static String AsciiToBinary(String asciiString) {

		byte[] bytes = asciiString.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes) {
			int tempVal = b;
			for (int i = 0; i < 8; i++) {
				binary.append((tempVal & 128) == 0 ? 0 : 1);
				tempVal <<= 1;
			}

		}
		return binary.toString();
	}

	public static void main(String args[]) {
		BigInteger keyElements[] = setUpKeyGen();
		System.out.println("$$$$$$$$$$$$$$$$$$$");
		System.out.println("Main Method ");
		System.out.println("$$$$$$$$$$$$$$$$$$$");
		String files[] = READ_FILES("plaintext.txt");
		String PLAIN_TEXT_FILE = files[0];
		System.out.println("PLN TXT LENGTH:"+PLAIN_TEXT_FILE.length());
		String PLAIN_TEXT[] = PLAIN_TEXT_FILE.split("(?<=\\G.{4})");
		BigInteger CIPHER_TEXT[] = null;
		System.out.println("Length:" + PLAIN_TEXT.length);
		
		for (int i = 0; i < PLAIN_TEXT.length; i++) {
			System.out.println("Plain Text:"+PLAIN_TEXT[i]);
			CIPHER_TEXT = wsu_Encryption(PLAIN_TEXT[i], keyElements[0],
					keyElements[1], keyElements[3]);			
			wsu_Decryption(CIPHER_TEXT[0], CIPHER_TEXT[1], keyElements[1],
					keyElements[2]);
		}		

		

	}
}
