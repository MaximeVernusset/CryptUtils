package vernusset.cryptUtils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import vernusset.cryptUtils.encryptableObjects.Encryptable;
import vernusset.cryptUtils.exceptions.ConflictingAsymmetricEncryptionAlgorithmsException;
import vernusset.cryptUtils.exceptions.NotEncryptableException;

/**
 *  Asymmetric encryption implementation, using RSA.
 * 
 * @author Maxime VERNUSSET
 *
 */
public class AsymmetricEncryptionMethod extends EncryptionMethod {

	/**
	 * 
	 * List of supported asymmetric algorithms and their key pair size.
	 * Only RSA supported for now.
	 */
	public static enum Algorithm implements EncryptionAlgorithm {

		RSA_ECB_PKCS1Padding_1024 ("RSA/ECB/PKCS1Padding", 1024),
		RSA_ECB_PKCS1Padding_2048 ("RSA/ECB/PKCS1Padding", 2048),
		RSA_ECB_PKCS1Padding_3072 ("RSA/ECB/PKCS1Padding", 3072),
		RSA_ECB_OAEPWithSHA_1AndMGF1Padding_1024 ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", 1024),
		RSA_ECB_OAEPWithSHA_1AndMGF1Padding_2048 ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", 2048),
		RSA_ECB_OAEPWithSHA_1AndMGF1Padding_3072 ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", 3072),
		RSA_ECB_OAEPWithSHA_256AndMGF1Padding_1024 ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", 1024),
		RSA_ECB_OAEPWithSHA_256AndMGF1Padding_2048 ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", 2048),
		RSA_ECB_OAEPWithSHA_256AndMGF1Padding_3072 ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", 3072);
		
		private final String name;
		private final int keySize;
		
		private Algorithm(String name, int keySize) {
			this.name = name;
			this.keySize = keySize;
		}

		@Override
		public String getName() {
			return this.name;
		}
		
		@Override
		public int getKeySize() {
			return this.keySize;
		}
		
		@Override
		public String getAlgo() {
			return this.name.split("/")[0];
		}
		
		@Override
		public String toString() {
			return this.getName() + " with " + this.getKeySize() + " bits key pair size";
		}
	}
	
	
	/**
	 * Public/private key pair of class instance.
	 * Public key to be transmitted to correspondent so he can encrypt messages.
	 * Private key to keep secret to decrypt messages.
	 */
	protected KeyPair keyPair;
	
	/**
	 * Correspondent's public key to be able to encrypt message to his attention.
	 */
	protected PublicKey correspondentPublicKey;
	
	
	/**
	 * Constructor.
	 * @param algo asymmetric algorithm to use
	 * @param keyPair private/public key pair of instance
	 * @param correspondentPublicKey Public key of correspondent to be able to encrypt messages to his attention
	 * @throws ConflictingAsymmetricEncryptionAlgorithmsException
	 */
	public AsymmetricEncryptionMethod(Algorithm algo, KeyPair keyPair, PublicKey correspondentPublicKey) throws ConflictingAsymmetricEncryptionAlgorithmsException  {
		super(algo);
		
		if(algo.getAlgo().equals(keyPair.getPublic().getAlgorithm()) && algo.getAlgo().equals(keyPair.getPrivate().getAlgorithm())) {
			if(algo.getAlgo().equals(correspondentPublicKey.getAlgorithm())) {
				this.keyPair = keyPair;
				this.correspondentPublicKey = correspondentPublicKey;
			} else {
				throw new ConflictingAsymmetricEncryptionAlgorithmsException("The given correspondent public key does not match with the desired algorithm. Desired algorithm: " + algo.getAlgo() + ", correspondent public key algorithm: " + correspondentPublicKey.getAlgorithm());
			}
		} else {
			throw new ConflictingAsymmetricEncryptionAlgorithmsException(algo.getAlgo(), keyPair.getPrivate().getAlgorithm(), keyPair.getPublic().getAlgorithm());
		}
	}

	/**
	 * Getter.
	 * @return the public key from the key pair
	 */
	public PublicKey getPublicKey() {
		return this.keyPair.getPublic();
	}
	
	/**
	 * Getter.
	 * @return the private key from the key pair (private key is private thus not obtainable from outside this class or inheriting classes).
	 */
	protected PrivateKey getPrivateKey() {
		return this.keyPair.getPrivate();
	}

	/**
	 * Getter.
	 * @return the correspondent's public key
	 */
	public PublicKey getCorrespondentPublicKey() {
		return this.correspondentPublicKey;
	}
	
	/**
	 * Setter.
	 * @param correspondentPublicKey Correspondent's public key to be able to crypt message to his attention
	 */
	public void setCorrespondentPublicKey(PublicKey correspondentPublicKey) {
		this.correspondentPublicKey = correspondentPublicKey;
	}
	
	/**
	 * Setter.
	 * @param keyPair private/public key pair of class instance
	 */
	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	/**
	 * Static method to build a private/public key pair, if needed some.
	 * @param algo algorithm for which the key pair is desired
	 * @return private/public key pair
	 */
	public static KeyPair buildKeyPair(Algorithm algo) {
		KeyPairGenerator keyPairGen;
		try {
			keyPairGen = KeyPairGenerator.getInstance(algo.getAlgo());
			keyPairGen.initialize(algo.getKeySize());
			return keyPairGen.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
    }
	
	/**
	 * Asymmetric implementation of the method defined in {@link vernusset.cryptUtils.EncryptionMethod EncryptionMethod}.
	 * @throws InvalidKeyException 
	 * @throws NotEncryptableException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	@Override
	protected byte[] encrypt(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException {
    	super.cipher.init(Cipher.ENCRYPT_MODE, this.correspondentPublicKey);
        return super.cipher.doFinal(super.serialize(data));
	}

	@Override
	public byte[] encryptToBytesArray(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException  {
        return this.encrypt(data);
	}

	@Override
	public String encryptToBase64String(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException {
        return Base64.getEncoder().encodeToString(this.encrypt(data));
	}

	/**
	 * Asymmetric implementation of the method defined in {@link vernusset.cryptUtils.EncryptionMethod EncryptionMethod}.
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws NotEncryptableException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws ClassNotFoundException 
	 */
	@Override
	protected Encryptable decrypt(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException  {
    	super.cipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());
        return super.deserialize(super.cipher.doFinal(encryptedData));
	}

	@Override
	public Encryptable decryptFromBytesArray(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException {
    	return this.decrypt(encryptedData);
	}

	@Override
	public Encryptable decryptFromBase64String(String encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException  {
    	return this.decrypt(Base64.getDecoder().decode(encryptedData));
	}
}
