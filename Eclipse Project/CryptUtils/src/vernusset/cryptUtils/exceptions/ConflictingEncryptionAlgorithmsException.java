package vernusset.cryptUtils.exceptions;

/**
 * 
 * Abstract exception for conflicting encryption algorithm (when the given key corresponding algo does not match the desired algo).
 * 
 * @author Maxime VERNUSSET
 *
 */
abstract public class ConflictingEncryptionAlgorithmsException extends Exception {
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 * @param message exception message
	 */
	public ConflictingEncryptionAlgorithmsException(String message) {
		super(message);
	}

}
