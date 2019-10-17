/**
 * 
 */
package no.hvl.dat159.crypto;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;


/**
 * @author tdoy
 *
 */
public class KeyStores {


	/**
	 * 
	 * @param keystore
	 * @param alias
	 * @param keystorepassword
	 * @return
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableEntryException 
	 */
	public static PrivateKey getPrivateKeyFromKeyStore(String keystore, String alias, String keystorepassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		char[] password = keystorepassword.toCharArray();

		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(keystore);
			ks.load(fis, password);
		} finally {
			if (fis != null) {
				fis.close();
			}
		}

		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();

		return myPrivateKey;
	}
}
