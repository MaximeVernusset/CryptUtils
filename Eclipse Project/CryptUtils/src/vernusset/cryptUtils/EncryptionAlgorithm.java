package vernusset.cryptUtils;

/**
 * 
 * Interface defining a contract for an enumeration of encryption algorithms (symmetric or asymmetric).
 * 
 * @author Maxime VERNUSSET
 *
 */
public interface EncryptionAlgorithm {

	/**
	 * 
	 * @return full algo name
	 */
	public String getName();
	
	/**
	 * 
	 * @return algo secret key size
	 */
	public int getKeySize();
	
	/**
	 * 
	 * @return algo short name
	 */
	public String getAlgo();
	
	/**
	 * 
	 * @return string representation of algo
	 */
	public String toString();
}
