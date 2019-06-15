package test.vernusset.crypUtils.sampleEncryptableObjects;

import vernusset.cryptUtils.encryptableObjects.Encryptable;

public class SampleEncryptableObject implements Encryptable {

	private static final long serialVersionUID = 1L;
	private int i;
	private String j;

	public SampleEncryptableObject(int i, String j) {
		this.i = i;
		this.j = j;
	}

	public int getI() {
		return i;
	}
	public String getJ() {
		return j;
	}
	
	@Override
	public String toString() {
		return ("[" + this.getClass().getSimpleName() + "]{i=" + this.i + ", j=\"" + this.j + "\"}");
	}
	
	@Override
	public boolean equals(Object obj) {
		if(!this.getClass().equals(obj.getClass())) return false;
		if(this.i != ((SampleEncryptableObject)obj).getI()) return false;
		if(!this.j.equals(((SampleEncryptableObject)obj).getJ())) return false;
		
		return true;
	}
}
