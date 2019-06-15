package vernusset.cryptUtils.exceptions;

/**
 * Exception thrown when the given key pair corresponding asymmetric encryption algorithm does not match the desired algorithm to use.
 * 
 * @author Maxime VERNUSSET
 *
 */
public class ConflictingAsymmetricEncryptionAlgorithmsException extends ConflictingEncryptionAlgorithmsException {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 * @param message custom message
	 */
	public ConflictingAsymmetricEncryptionAlgorithmsException(String message) {
		super(message);
	}
	
	/**
	 * Constructor.
	 * @param desiredAlgoName desired asymmetric encryption algorithm to use
	 * @param givenPrivateKeyCorrespondingAlgo given key pair private key corresponding algorithm
	 * @param givenPublicKeyCorrespondingAlgo given key pair public key corresponding algorithm
	 */
	public ConflictingAsymmetricEncryptionAlgorithmsException(String desiredAlgoName, String givenPrivateKeyCorrespondingAlgo, String givenPublicKeyCorrespondingAlgo) {
		super("The given key pair does not match with the desired algorithm. Desired algorithm: " + desiredAlgoName + ", private key algorithm: " + givenPrivateKeyCorrespondingAlgo + ", public key algorithm: " + givenPublicKeyCorrespondingAlgo);
	}

}
