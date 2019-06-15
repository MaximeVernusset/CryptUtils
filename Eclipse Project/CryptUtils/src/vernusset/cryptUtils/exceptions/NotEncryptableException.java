package vernusset.cryptUtils.exceptions;

/**
 * 
 * Exception thrown when trying to serialize an object that does not implement the Encryptable interface.
 * 
 * @author Maxime VERNUSSET
 *
 */
public class NotEncryptableException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public NotEncryptableException() {
		super("Your object must implement the Encryptable interface");
	}
}
