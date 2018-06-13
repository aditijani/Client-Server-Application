
//package network_security_1;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bob {
	private static Socket socket;
	static BufferedReader br = null;
	static BufferedWriter bw = null;
	KeyPair kp = null;
	SecretKey short_sec_key = null;

	public static void main(String[] args) throws Exception {
		Bob bob = new Bob();
		Alice alice = new Alice();
		AES aes = new AES();
		bob.initializeAliceKey();

		// Join socket created by Alice
		Socket s = new Socket("localhost", 1046);
		DataInputStream din = new DataInputStream(s.getInputStream());
		DataOutputStream dout = new DataOutputStream(s.getOutputStream());
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String algo_exchange = "", algo_exchange_conf = "", alice_pub_str = "";

		algo_exchange = ":ka dh-secp224r1+nocert+aes128/cbc";
		dout.writeUTF(algo_exchange);
		dout.flush();

		algo_exchange_conf = din.readUTF();
		System.out.println("Alice says " + algo_exchange_conf);

		// reads alice_public_key
		alice_pub_str = din.readUTF();

		// pushes Bob's public key into the socket
		String bob_pub_str = Base64.getEncoder().encodeToString(bob.kp.getPublic().getEncoded());
		dout.writeUTF(bob_pub_str);
		dout.flush();

		// Decode Alice's Base64 key to PublicKey data type
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		byte[] alice_pub_byte = Base64.getDecoder().decode(alice_pub_str);
		EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(alice_pub_byte);
		PublicKey alice_pub_key = keyFactory.generatePublic(pubKeySpec);

		SecretKey bob_sec_key = alice.combine(bob.kp.getPrivate(), alice_pub_key);

		// converts 32byte Secret key(bob) to 16 byte key
		byte[] smallKey = Arrays.copyOfRange(bob_sec_key.getEncoded(), 16, 32);
		bob.short_sec_key = new SecretKeySpec(smallKey, 0, smallKey.length, "AES");

		String str = "";
		byte[] enc_str;
		while (!str.equals("exit")) {

			str = din.readUTF();
			byte[] dec_data = aes.AESDecryption(Base64.getDecoder().decode(str.getBytes()), bob.short_sec_key);
			System.out.println("Alice : " + new String(dec_data));
			System.out.print("Bob : ");
			str = br.readLine();
			enc_str = Base64.getEncoder().encode(aes.AESEncryption(str.getBytes(), bob.short_sec_key));
			dout.writeUTF(new String(enc_str));
			dout.flush();

			// try {
			// do {
			// } while (din.available() > 0);
			// System.out.println("Received Enc Data: " + str);
			// System.out.println(new String(aes.AESDecryption(str.getBytes(),
			// bob.short_sec_key)));
			// byte[] encData=str.getBytes("UTF-8");
			// byte[] encoded = str.getBytes("UTF8");
			// System.out.println(dec_data.length);
			// String decrypted = new String(dec_data);
			// } catch (Exception e) {
			// continue;
			// }
			// enc_str =
			// Base64.getEncoder().encode(aes.AESEncryption(str.getBytes(),
			// bob.short_sec_key));
		}

		dout.close();
		s.close();

	}

	public void initializeAliceKey() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			kpg.initialize(512);
			kp = kpg.genKeyPair();
		} catch (Exception e) {

		}
	}
}