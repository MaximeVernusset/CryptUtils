package vernusset.cryptUtils.encryptableObjects;

/**
 * 
 * String wrapping class providing the ability to encrypt/decrypt a string.
 * 
 * @author Maxime VERNUSSET
 *
 */
public class EncryptableString implements Encryptable {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Wrapped string.
	 * Willingly set public because this is just a wrapper.
	 * Thus can be accessed either directly or by getter/setter.
	 */
	public String string;
	
	/**
	 * Constructor.
	 * @param string wrapped string to encrypt/decrypt
	 */
	public EncryptableString(String string) {
		this.string = string;
	}
	
	/**
	 * Getter.
	 * @return wrapped string
	 */
	public String getString() {
		return this.string;
	}
	
	/**
	 * Setter.
	 * @param string string to wrap
	 */
	public void setString(String string) {
		this.string = string;
	}
	
	@Override
	public String toString() {
		return ("[" + this.getClass().getSimpleName() + "]{string=\"" + this.string + "\"}");
	}
	
	@Override
	public boolean equals(Object obj) {
		if(this.getClass() != obj.getClass()) return false;
		if(!this.string.equals(((EncryptableString)obj).string)) return false;
		
		return true;
	}

}
