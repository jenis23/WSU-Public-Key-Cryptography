/**
 * @author Jenis Modi
 * Instructions:
 * @Package name : wsu.cs527.project2
 * Keep prikey.txt and pubkey.txt in project folder
 * 
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
	private final static int certainty = 40;
<<<<<<< HEAD
	final static String FILE_NAME = "plaintext.txt";
	final static String PUB_KEY_FILE = "pubkey.txt";
	final static String PRI_KEY_FILE = "prikey.txt";
	final static String CIPHER_TEXT_FILE = "ctext.txt";
	final static String DECIPHER_TEXT_FILE = "dtext.txt";
=======
>>>>>>> bc20700ebdecd3c1ffb271f4392e97c35a50199f

	/**
	 * Encryption
	 * 
	 * @param PLAIN_TEXT
	 * @param g
	 * @param p
	 * @param e2
	 * @return C1 and C2
	 */
	private static BigInteger[] wsu_Encryption(String PLAIN_TEXT, BigInteger g,
			BigInteger p, BigInteger e2) {
		System.out.println("**********************");
		System.out.println("WSU_ENCRYPTION");
		System.out.println("**********************");
		String binaryPlnTxt = AsciiToBinary(PLAIN_TEXT);

		for (int i = 0; i < blockSize; i++) {
			if (binaryPlnTxt.length() != blockSize) {
				binaryPlnTxt = binaryPlnTxt.concat("0");
			}
		}
		System.out.println("Binary PlainText:" + binaryPlnTxt);
		/**
		 * Choose random value k from {0,....,p-1}
		 */
		BigInteger k = randomValue(BigInteger.ZERO, p.subtract(BigInteger.ONE));
		System.out.println("Random Value K:" + k);
		/**
		 * C1 = g^k mod p
		 */
		BigInteger C1 = g.modPow(k, p);
		/**
		 * C2 = e2^k * messageBlock mod p According to Number Theory, This is
		 * equivalent to C2 = [(e2^k mod p) * (messageBlock mod p)] mod p
		 */

		int decValue = Integer.parseInt(binaryPlnTxt, 2);
		String strDecValue = Integer.toString(decValue);
		System.out.println("Plain text Decimal Value: " + decValue);

		BigInteger C2 = ((e2.modPow(k, p))
				.multiply((new BigInteger(strDecValue)).modPow(BigInteger.ONE,
						p))).mod(p);
		System.out.println("C1:" + C1);
		System.out.println("C2:" + C2);

		BigInteger CipherText[] = new BigInteger[2];
		CipherText[0] = C1;
		CipherText[1] = C2;
		return CipherText;
	}

<<<<<<< HEAD
	/**
	 * Decryption
	 * 
	 * @param C1
	 * @param C2
	 * @param p
	 * @param d
	 * @return Ascii text
	 */
=======
>>>>>>> bc20700ebdecd3c1ffb271f4392e97c35a50199f
	private static String wsu_Decryption(BigInteger C1, BigInteger C2,
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
		if (binPlainText.length() != blockSize) {
			binPlainText = "0".concat(binPlainText);
		}
		/**
		 * Converting Binary to Ascii
		 */
		String[] Dec_Ascii_Value = new String[4];
		Dec_Ascii_Value[0] = Character.toString((char) Integer.parseInt(
				binPlainText.substring(0, 8), 2));
		Dec_Ascii_Value[1] = Character.toString((char) Integer.parseInt(
				binPlainText.substring(8, 16), 2));
		Dec_Ascii_Value[2] = Character.toString((char) Integer.parseInt(
				binPlainText.substring(16, 24), 2));
		Dec_Ascii_Value[3] = Character.toString((char) Integer.parseInt(
				binPlainText.substring(24, 32), 2));
		String AsciiText = Dec_Ascii_Value[0].concat(Dec_Ascii_Value[1])
				.concat(Dec_Ascii_Value[2]).concat(Dec_Ascii_Value[3]);

		System.out.println("Ascii Text:" + AsciiText);
		System.out.println("Deciphered Value in Decimal:" + Plain_Text);
		System.out.println("Deciphered Value in Binary:" + binPlainText);

		return AsciiText;

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
				randomNo = new BigInteger(blockSize, random);
			} while (!(randomNo.isProbablePrime(certainty) && (randomNo
					.mod(modNumber).equals(modEqual))));

			primeNumber = (generator.multiply(randomNo))
					.add(new BigInteger("1"));
		} while (!(primeNumber.isProbablePrime(certainty) && primeNumber
				.bitLength() > blockSize));
		return primeNumber;
	}

	/**
	 * To get the random value in between lowLimit and HighLimit of BigIntegers
	 * 
	 * @param lowLimit
	 * @param highLimit
	 * @return
	 */
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

	/**
	 * Key Gen Setup
	 * 
	 * @return g,p,d,e2
	 */
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

		File pubFile = new File(PUB_KEY_FILE);
		File priFile = new File(PRI_KEY_FILE);

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
			System.out.println("Setup and Key Generation");
			System.out.println("**************************");
			System.out.println("Generator g:" + g);
			System.out.println("p:" + p);
			System.out.println("d:" + d);
			System.out.println("e2:" + e2);
			System.out.println("**************************");

		} catch (IOException e) {
			e.printStackTrace();
		}
		return keyElements;

	}

	/**
	 * Reads the plaintext.txt file
	 * 
	 * @param fileName
	 * @return
	 */
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

		} catch (Exception e) {
			System.err.println("Error: " + e);
		}
		return s;

	}

	/**
	 * Converts Ascii to Binary
	 * 
	 * @param asciiString
	 * @return Binary String
	 */
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
		System.out.println("**************************");
		System.out.println("Main Method ");
		System.out.println("**************************");
<<<<<<< HEAD
		String files[] = READ_FILES(FILE_NAME);
=======
		String files[] = READ_FILES("plaintext.txt");
>>>>>>> bc20700ebdecd3c1ffb271f4392e97c35a50199f
		String PLAIN_TEXT_FILE = files[0];
		if (PLAIN_TEXT_FILE.length() != 0) {
			String PLAIN_TEXT[] = PLAIN_TEXT_FILE.split("(?<=\\G.{4})");
			BigInteger CIPHER_TEXT[] = null;
			String recoveredMessage = new String();

<<<<<<< HEAD
			File cipherFile = new File(CIPHER_TEXT_FILE);
			File decipherFile = new File(DECIPHER_TEXT_FILE);

			try {
				if (!cipherFile.exists())
					cipherFile.createNewFile();

				if (!decipherFile.exists())
					decipherFile.createNewFile();

				FileWriter cipherTextFile = new FileWriter(cipherFile.getName());
				FileWriter decipherTextFile = new FileWriter(
						decipherFile.getName());

				BufferedWriter cipherContents = new BufferedWriter(
						cipherTextFile);
				BufferedWriter decipherContents = new BufferedWriter(
						decipherTextFile);

				for (int i = 0; i < PLAIN_TEXT.length; i++) {
					CIPHER_TEXT = wsu_Encryption(PLAIN_TEXT[i], keyElements[0],
							keyElements[1], keyElements[3]);
					cipherContents.write(CIPHER_TEXT[1].toString() + " "
							+ CIPHER_TEXT[0].toString()+" ");
					recoveredMessage = recoveredMessage.concat(wsu_Decryption(
							CIPHER_TEXT[0], CIPHER_TEXT[1], keyElements[1],
							keyElements[2]));
				}
				decipherContents.write(recoveredMessage);

				cipherContents.close();
				decipherContents.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
=======
			for (int i = 0; i < PLAIN_TEXT.length; i++) {
				CIPHER_TEXT = wsu_Encryption(PLAIN_TEXT[i], keyElements[0],
						keyElements[1], keyElements[3]);
				recoveredMessage = recoveredMessage.concat(wsu_Decryption(
						CIPHER_TEXT[0], CIPHER_TEXT[1], keyElements[1],
						keyElements[2]));
			}

>>>>>>> bc20700ebdecd3c1ffb271f4392e97c35a50199f
			System.out.println("*******************************************");
			System.out.println("Final Recovered Message:" + recoveredMessage);
			System.out.println("*******************************************");
		} else {
			System.out.println("No Message added in Text file");
		}

	}
}
