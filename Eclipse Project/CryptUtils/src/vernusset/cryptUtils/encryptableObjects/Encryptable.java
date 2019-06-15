package vernusset.cryptUtils.encryptableObjects;

import java.io.Serializable;

/**
 * 
 * Interface to implement when a class needs to be encryptable.
 * 
 * @author Maxime VERNUSSET
 * 
 */
public interface Encryptable extends Serializable {
	String toString();
	boolean equals(Object obj);
}
