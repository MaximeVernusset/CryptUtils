package vernusset.cryptUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import vernusset.cryptUtils.encryptableObjects.Encryptable;
import vernusset.cryptUtils.exceptions.NotEncryptableException;


/**
 * 
 * This abstract class wraps a cipher, 
 * allows to serialize/deserialize objects, 
 * and defines methods to encrypt/decrypt objects (to be implemented by child classes).
 *
 * @author Maxime VERNUSSET
 * 
 */
public abstract class EncryptionMethod {
	
	/**
	 * Cipher used to provide encryption/decryption methods.
	 */
	protected Cipher cipher;
	
	
	/**
	 * Constructor.
	 * @param algo Algorithm to be used by cipher
	 */
	protected EncryptionMethod(EncryptionAlgorithm algo) {
  		try {
			this.cipher = Cipher.getInstance(algo.getName());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
  	}

	
  	/**
  	 * 
  	 * @param object any object that implements the Encryptable interface
  	 * @return serialized object
  	 * @throws IOException
  	 * @throws NotEncryptableException 
  	 */
  	protected byte[] serialize(Encryptable object) throws IOException, NotEncryptableException {
    	try {
    		ByteArrayOutputStream out = new ByteArrayOutputStream();
    		ObjectOutputStream os = new ObjectOutputStream(out);
    		os.writeObject(object);
    		return out.toByteArray();
    	} catch (NotSerializableException e) {
    		throw new NotEncryptableException();
    	}
    }
    
  	/**
  	 * 
  	 * @param data serialized data
  	 * @return deserialized object
  	 * @throws NotEncryptableException 
  	 * @throws IOException 
  	 * @throws ClassNotFoundException
  	 */
  	protected Encryptable deserialize(byte[] data) throws NotEncryptableException, IOException, ClassNotFoundException   {
  		try {
	        ByteArrayInputStream in = new ByteArrayInputStream(data);
	        ObjectInputStream is = new ObjectInputStream(in);
	        return (Encryptable)is.readObject();
  		} catch (NotSerializableException e) {
    		throw new NotEncryptableException();
  		}
    }
    
  	/**
  	 * 
  	 * Main encryption method
  	 * @param data object to encrypt
  	 * @return bytes array encrypted data
  	 */
  	protected abstract byte[] encrypt(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException;
  	
    /**
     * 
     * @param data any object that implements the Encryptable interface
     * @return encrypted data
  	 * @throws InvalidKeyException
  	 * @throws IllegalBlockSizeException
  	 * @throws BadPaddingException
  	 * @throws IOException
  	 * @throws NotEncryptableException
  	 */
  	public abstract byte[] encryptToBytesArray(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException;
    
  	/**
  	 * 
  	 * @param data any object that implements the Encryptable interface
  	 * @return encrypted data base64 encoded
  	 * @throws InvalidKeyException
  	 * @throws IllegalBlockSizeException
  	 * @throws BadPaddingException
  	 * @throws IOException
  	 * @throws NotEncryptableException
  	 */
  	public abstract String encryptToBase64String(Encryptable data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NotEncryptableException;
  	
  	/**
  	 * main decryption method
  	 * @param encryptedData bytes array encrypted data
  	 * @return decrypted object
  	 * @throws InvalidKeyException
  	 * @throws ClassNotFoundException
  	 * @throws IllegalBlockSizeException
  	 * @throws BadPaddingException
  	 * @throws NotEncryptableException
  	 * @throws IOException
  	 */
    protected abstract Encryptable decrypt(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException;
    
    /**
     * 
     * @param encryptedData bytes array encrypted data
     * @return decrypted data
     * @throws InvalidKeyException
     * @throws ClassNotFoundException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NotEncryptableException
     * @throws IOException
     */
    public abstract Encryptable decryptFromBytesArray(byte[] encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException;
    
    /**
     * 
     * @param encryptedData base64 encoded encrypted data
     * @return decrypted data
     * @throws InvalidKeyException
     * @throws ClassNotFoundException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NotEncryptableException
     * @throws IOException
     */
    public abstract Encryptable decryptFromBase64String(String encryptedData) throws InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NotEncryptableException, IOException;
}
