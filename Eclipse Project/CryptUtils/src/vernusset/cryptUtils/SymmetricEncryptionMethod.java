package vernusset.cryptUtils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import vernusset.cryptUtils.encryptableObjects.Encryptable;
import vernusset.cryptUtils.exceptions.ConflictingSymmetricEncryptionAlgorithmsException;
import vernusset.cryptUtils.exceptions.NotEncryptableException;
import vernusset.cryptUtils.exceptions.WrongSymmetricKeySizeException;


/**
 * 
 * Symmetric encryption implementation, using AES.
 * 
 * @author Maxime VERNUSSET
 * 
 */
public class SymmetricEncryptionMethod extends EncryptionMethod {
	
	/**
	 * 
	 * List of supported symmetric algorithms and their secret key size.
	 * Only AES supported for now.
	 */
	public static enum SymmetricAlgorithm implements EncryptionAlgorithm {

		AES_ECB_PKCS5PADDING_128 ("AES/ECB/PKCS5Padding", 128),
		AES_ECB_PKCS5PADDING_192 ("AES/ECB/PKCS5Padding", 192),
		AES_ECB_PKCS5PADDING_256 ("AES/ECB/PKCS5Padding", 256);
		
		private final String name;
		private final int keySize;
		
		private SymmetricAlgorithm(String name, int keySize) {
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
			return this.getName() + " with " + this.getKeySize() + " bits secret key size";
		}
	}
	
	
	/**
	 * Algorithm's secret key used.
	 */
	protected SecretKey key;
	

	/**
	 * Constructor.
	 * @param algo desired algo to use
	 * @param key bytes array secret key
	 * @throws WrongSymmetricKeySizeException 
	 */
	public SymmetricEncryptionMethod(SymmetricAlgorithm algo, byte[] key) throws WrongSymmetricKeySizeException  {
  		super(algo);
		if(key.length*8 == algo.getKeySize()) { //Bytes to bits
  			this.key = new SecretKeySpec(key, algo.getAlgo());
  		} else {
  			throw new WrongSymmetricKeySizeException(algo.getKeySize(), key.length*8);
  		}
  	}
	
	/**
	 * Constructor.
	 * @param algo desired algo to use
	 * @param key secret key
	 * @throws ConflictingSymmetricEncryptionAlgorithmsException 
	 * @throws WrongSymmetricKeySizeException 
	 */
	public SymmetricEncryptionMethod(SymmetricAlgorithm algo, SecretKey key) throws ConflictingSymmetricEncryptionAlgorithmsException, WrongSymmetricKeySizeException  {
  		super(algo);
		if(key.getEncoded().length*8 == algo.getKeySize()) { //Bytes to bits
			if(key.getAlgorithm().contentEquals(algo.getAlgo())) {
				this.key = key;
			} else {
	  			throw new ConflictingSymmetricEncryptionAlgorithmsException(algo.getAlgo(), key.getAlgorithm());
			}
  		} else {
  			throw new WrongSymmetricKeySizeException(algo.getKeySize(), key.getEncoded().length*8);
  		}
  	}
	
	/**
	 * Static method to build a secret key, if needed some.
	 * @param algo algorithm for which the secret key is desired
	 * @return private/public key pair
	 */
	public static SecretKey buildSecretKey(SymmetricAlgorithm algo) {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(algo.getAlgo());
			keyGen.init(algo.getKeySize());
			return keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
    }

	/**
	 * Symmetric implementation of the method defined in {@link vernusset.cryptUtils.EncryptionMethod EncryptionMethod}.
	 * @throws InvalidKeyException 
	 * @throws NotEncryptableException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
    @Override
    protected byte[] encrypt(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException  {
    	super.cipher.init(Cipher.ENCRYPT_MODE, this.key);
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
	 * Symmetric implementation of the method defined in {@link vernusset.cryptUtils.EncryptionMethod EncryptionMethod}.
     * @throws InvalidKeyException 
     * @throws IOException 
     * @throws NotEncryptableException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws ClassNotFoundException 
	 */
    @Override
    protected Encryptable decrypt(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException  {
    	super.cipher.init(Cipher.DECRYPT_MODE, this.key);
        return super.deserialize(super.cipher.doFinal(encryptedData));
    }
    
    @Override
    public Encryptable decryptFromBytesArray(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException  {
    	return this.decrypt(encryptedData);
    }
    
    @Override
    public Encryptable decryptFromBase64String(String encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException  {
    	return this.decrypt(Base64.getDecoder().decode(encryptedData));
    }
}
