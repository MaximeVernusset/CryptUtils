package vernusset.cryptUtils.exceptions;

/**
 * 
 * Exception thrown when the given secret key corresponding symmetric encryption algorithm does not match the desired algorithm to use.
 * 
 * @author Maxime VERNUSSET
 *
 */
public class ConflictingSymmetricEncryptionAlgorithmsException extends ConflictingEncryptionAlgorithmsException {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 * @param desiredAlgoName desired symmetric encryption algorithm to use
	 * @param givenKeyCorrespondingAlgo given key corresponding algorithm
	 */
	public ConflictingSymmetricEncryptionAlgorithmsException(String desiredAlgoName, String givenKeyCorrespondingAlgo) {
		super("The given secret key does not match with the desired algorithm. Desired algorithm: " + desiredAlgoName + ", secret key algorithm: " + givenKeyCorrespondingAlgo);
	}

}