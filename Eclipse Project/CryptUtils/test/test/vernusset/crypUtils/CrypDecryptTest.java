package test.vernusset.crypUtils;

import java.security.KeyPair;
import java.util.Base64;

import javax.crypto.SecretKey;

import test.vernusset.crypUtils.sampleEncryptableObjects.*;
import vernusset.cryptUtils.*;
import vernusset.cryptUtils.encryptableObjects.*;


/**
 * 
 * @author Maxime VERNUSSET
 *
 */
public class CrypDecryptTest {
	
	private enum EncryptionMode {
		SYMETRIC, ASYMETRIC;
	}
	
	private enum EncryptionOutputFormat {
		BASE64, BYTES_ARRAY;
	}
	

	/**
	 * Symmetric algorithm to use.
	 */
	private final SymmetricEncryptionMethod.Algorithm SYMETRIC_ENCRYPTION_ALGO = SymmetricEncryptionMethod.Algorithm.AES_ECB_PKCS5PADDING_256;

	/**
	 * Asymmetric algorithm to use.
	 */
	private final AsymmetricEncryptionMethod.Algorithm ASYMETRIC_ENCRYPTION_ALGO = AsymmetricEncryptionMethod.Algorithm.RSA_ECB_PKCS1Padding_3072;
	
	
	/**
	 * Symmetric encryption key used for testing.
	 */
	private SecretKey symmetricKey;
	
	/**
	 * Asymmetric encryption keypair used for testing.
	 */
	private KeyPair asymmetricKeyPair;
	
	
	/**
	 * Constructor. 
	 * Builds symmetric and asymmetric keys used for testing.
	 */
	public CrypDecryptTest() {
		System.out.println("Building test encryption keys...");

		//Symmetric key
		try {
			this.symmetricKey = SymmetricEncryptionMethod.buildSecretKey(this.SYMETRIC_ENCRYPTION_ALGO);
			System.out.println("[ok] Symmetric key pair (" + this.SYMETRIC_ENCRYPTION_ALGO.getKeySize() + " bits):");
			System.out.println("\t" + Base64.getEncoder().encodeToString(this.symmetricKey.getEncoded()));
		} catch (Exception e) {
			System.out.println("[failed] Symmetric key");
			e.printStackTrace();
			System.exit(-1);
		}
		
		//Asymmetric keys
		try {
			this.asymmetricKeyPair = AsymmetricEncryptionMethod.buildKeyPair(this.ASYMETRIC_ENCRYPTION_ALGO);
			System.out.println("[ok] Asymmetric key pair (" + this.ASYMETRIC_ENCRYPTION_ALGO.getKeySize() + " bits):");
			System.out.println("\tprivate: " + Base64.getEncoder().encodeToString(this.asymmetricKeyPair.getPrivate().getEncoded()));
			System.out.println("\tpublic: " + Base64.getEncoder().encodeToString(this.asymmetricKeyPair.getPublic().getEncoded()));
		} catch (Exception e) {
			System.out.println("[failed] Asymmetric key pair");
			e.printStackTrace();
			System.exit(-1);
		}

		System.out.println("\n");
	}
	
	
	/**
	 * Unit test function.
	 * @param testNumber
	 * @param mode symmetric or asymmetric
	 * @param input test data (can be any string or object that implements the Encryptable interface)
	 * @param format base64 or bytes array output format
	 * @return true if test passed, false otherwise
	 */
	private boolean test(int testNumber, EncryptionMode mode, Encryptable input, EncryptionOutputFormat format) {
		EncryptionMethod em = null;
		EncryptionAlgorithm algoUsed = null;
		Object output = null;
		boolean passed = false;

		try {
			switch(mode) {
				case SYMETRIC: 
					algoUsed = this.SYMETRIC_ENCRYPTION_ALGO;
					em = new SymmetricEncryptionMethod(this.SYMETRIC_ENCRYPTION_ALGO, this.symmetricKey);
					break;
				
				case ASYMETRIC:
					algoUsed = this.ASYMETRIC_ENCRYPTION_ALGO; 
					em = new AsymmetricEncryptionMethod(this.ASYMETRIC_ENCRYPTION_ALGO, this.asymmetricKeyPair, this.asymmetricKeyPair.getPublic());
					break;
			}
			
			System.out.println("Test n°" + testNumber + " - " + mode.toString() + " encryption using " + algoUsed.toString() + " - " + format.toString() + " output");
			System.out.println("\tInput: " + input.toString());
			System.out.print("\tEncrypted: ");

			switch(format) {
				case BASE64:
					String base64Encrypted = em.encryptToBase64String(input);
					System.out.println(base64Encrypted.toString());
					output = em.decryptFromBase64String(base64Encrypted);
					break;
				
				case BYTES_ARRAY:
					byte[] bytesArrayEncrypted = em.encryptToBytesArray(input);
					System.out.println(bytesArrayEncrypted.toString());
					output = em.decryptFromBytesArray(bytesArrayEncrypted);
					break;
			}
			
			System.out.println("\tDecrypted: " + output.toString());
			passed = input.equals(output);
		}
		catch (Exception e) {
			e.printStackTrace();
			passed = false;
		}
		finally {
			System.out.println(passed ? "PASSED" : "FAILED");
			System.out.println("\n");
		}
	
		return passed;
	}
	
	
	/**
	 * Function to launch series of units tests.
	 * @return true if all tests passed, false otherwise
	 */
	public boolean run() {
		int ran = 0, passed = 0;

		//Symmetric
		passed += this.test(++ran, EncryptionMode.SYMETRIC, new EncryptableString("String to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.SYMETRIC, new SampleEncryptableObject(ran, "Object to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.SYMETRIC, new SampleEncryptableObject(ran, "2nd object to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.SYMETRIC, new EncryptableString("2nd string to encrypt"), EncryptionOutputFormat.BYTES_ARRAY) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.SYMETRIC, new SampleEncryptableObject(ran, "3rd object to encrypt"), EncryptionOutputFormat.BYTES_ARRAY) ? 1 : 0;
		
		//Asymmetric
		passed += this.test(++ran, EncryptionMode.ASYMETRIC, new EncryptableString("String to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.ASYMETRIC, new SampleEncryptableObject(ran, "1st object to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.ASYMETRIC, new SampleEncryptableObject(ran, "2nd object to encrypt"), EncryptionOutputFormat.BASE64) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.ASYMETRIC, new EncryptableString("String to encrypt"), EncryptionOutputFormat.BYTES_ARRAY) ? 1 : 0;
		passed += this.test(++ran, EncryptionMode.ASYMETRIC, new SampleEncryptableObject(ran, "3rd object to encrypt"), EncryptionOutputFormat.BYTES_ARRAY) ? 1 : 0;
		
		System.out.println("--- " + passed + " out " + ran + " test" + (ran>1 ? "s" : "") + " passed ---\n");
		
		return passed == ran;
	}
	
	
	/**
	 * Class entry point.
	 * @param args not used
	 */
	public static void main(String[] args) {
		(new CrypDecryptTest()).run();
	}	
}
