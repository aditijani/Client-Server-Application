
//package network_security_1;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
	private static final String String = null;
	private static Socket socket;
	private static ServerSocket serverSocket;
	static BufferedReader br = null;
	static BufferedWriter bw = null;
	SecretKey short_sec_key = null;
	KeyPair kp = null;

	public static void main(String[] argv) throws Exception {
		Alice alice = new Alice();
		alice.initializeAliceKey();
		AES aes = new AES();

		// Socket config
		ServerSocket ss = new ServerSocket(1046);
		Socket s = ss.accept();
		DataInputStream din = new DataInputStream(s.getInputStream());
		DataOutputStream dout = new DataOutputStream(s.getOutputStream());
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String algo_exchange = "", algo_exchange_conf = "";
		String algo_exchange_2 = "", algo_exchange_conf_2 = "";

		algo_exchange = din.readUTF();
		System.out.println("Bob says: " + algo_exchange);

		// TimeUnit.SECONDS.sleep(3);

		algo_exchange_conf = "kaok dh-secp256r1+x509+aes128/gcm128";
		algo_exchange_conf_2 = "kaok dh-secp224r1+x509+aes128/gcm128";
		dout.writeUTF(algo_exchange_conf);
		dout.flush();

		// pushes Alice's public key into the socket
		String alice_pub_str = Base64.getEncoder().encodeToString(alice.kp.getPublic().getEncoded());
		dout.writeUTF(alice_pub_str);
		dout.flush();

		// reads bob's public key from the socket
		String bob_pub = din.readUTF();

		// Decode bob's Base64 key to PublicKey data type
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		byte[] bob_pub_byte = Base64.getDecoder().decode(bob_pub);
		EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bob_pub_byte);
		PublicKey bob_pub_key = keyFactory.generatePublic(pubKeySpec);

		// Generate secret key
		SecretKey secret = combine(alice.kp.getPrivate(), bob_pub_key);

		// converts 32byte Secret key(Alice) to 16 byte key
		byte[] smallKey = Arrays.copyOfRange(secret.getEncoded(), 16, 32);
		alice.short_sec_key = new SecretKeySpec(smallKey, 0, smallKey.length, "AES");

		// starting chat

		String dataStr, str = "";
		byte[] enc_str;
		System.out.print("Alice: ");
		while (!str.equals("exit")) {
			str = br.readLine();
			enc_str = Base64.getEncoder().encode(aes.AESEncryption(str.getBytes(), alice.short_sec_key));
			dataStr = new String(enc_str);
			dout.writeUTF(dataStr);
			dout.flush();
			dataStr = din.readUTF();
			System.out.println(
					"Bob : " + new String(aes.AESDecryption(Base64.getDecoder().decode(dataStr), alice.short_sec_key)));
			System.out.print("Alice :");
		}

		din.close();
		s.close();
		ss.close();
	}

	public void initializeAliceKey() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			kpg.initialize(512);
			kp = kpg.genKeyPair();
		} catch (Exception e) {

		}
	}

	public static SecretKey combine(PrivateKey private1, PublicKey public1)
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(private1);
		ka.doPhase(public1, true);
		SecretKey secretKey = ka.generateSecret("AES");
		// System.out.println("Secret key: " +
		// javax.xml.bind.DatatypeConverter.printHexBinary(secretKey.getEncoded()));
		return secretKey;
	}
}