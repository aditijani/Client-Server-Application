
//package network_security_1;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class AES {

	// SecretKey secretKey = null;
	public static void main(String[] argv) throws Exception {
		AES aes = new AES();
		byte[] c = aes.AESEncryption("hello".getBytes(), null);

	}

	public byte[] AESEncryption(byte[] Data, SecretKey secretKey) {
		byte[] cipherText = null;
		try {

			// AES defaults to AES/ECB/PKCS5Padding in Java 7
			Cipher aesCipher = Cipher.getInstance("AES");
			aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] byteCipherText = aesCipher.doFinal(Data);
			System.out.println(byteCipherText);
			return byteCipherText;
		} catch (Exception e) {
			System.out.println();
		}

		return cipherText;

		/**
		 * Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		 * 
		 * 
		 * KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		 * SecureRandom secureRandom = new SecureRandom(); int keyBitSize = 128;
		 * keyGenerator.init(keyBitSize, secureRandom);
		 * System.out.println("Data= "+Data); // System.out.println("Seret //
		 * Key="+Arrays.toString(secretKey.getEncoded()));
		 * 
		 * byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		 * IvParameterSpec ivspec = new IvParameterSpec(iv); //secretKey =
		 * keyGenerator.generateKey(); // System.out.println("Sec Len : " +
		 * secretKey.getEncoded().length); cipher.init(Cipher.ENCRYPT_MODE,
		 * secretKey, ivspec);
		 * 
		 * byte[] plainText = Data;
		 * 
		 * cipherText = cipher.doFinal(plainText);
		 * System.out.println(cipherText); // System.out.println("E"); //
		 * AESDecryption(cipherText, secretKey); //
		 * System.out.println("Encrypted: " + new String(cipherText, //
		 * "UTF-8")); // AES aes = new AES();
		 * 
		 * // aes.AESDecryption(cipherText, secretKey);
		 * 
		 * 
		 * //byte[] c= Base64.getEncoder().encode(cipherText); //String a=new
		 * String(c);
		 * 
		 * // byte[] d=Base64.getDecoder().decode(a.getBytes()); //
		 * AESDecryption(cipherText, secretKey);
		 **/

	}

	public byte[] AESDecryption(byte[] Data, SecretKey secretKeyx) {

		try {

			Cipher aesCipher = Cipher.getInstance("AES");
			aesCipher.init(Cipher.DECRYPT_MODE, secretKeyx);
			byte[] bytePlainText = aesCipher.doFinal(Data);
			System.out.println(bytePlainText);
			return bytePlainText;

		} catch (Exception w) {
			System.out.println("Error");
		}
		return null;
	}

}