package vernusset.cryptUtils.exceptions;

/**
 * 
 * Exception thrown when trying to instantiate a SymmetricEncryptionMethod with a secret key not matching the required algorithm key size (in bits).
 * 
 * @author Maxime VERNUSSET
 *
 */
public class WrongSymmetricKeySizeException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 * @param desiredAlgoKeySize secret key size of desired symmetric encryption algorithm to use
	 * @param givenKeySize given secret key size
	 */
	public WrongSymmetricKeySizeException(int desiredAlgoKeySize, int givenKeySize) {
		super("Wrong key size for specified algorithm. Expected: " + desiredAlgoKeySize + " Bits, Given: " + givenKeySize + " Bits.");
	}

}
