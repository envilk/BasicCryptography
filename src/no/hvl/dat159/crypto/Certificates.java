/**
 * 
 */
package no.hvl.dat159.crypto;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/**
 * @author tdoy
 *
 */
public class Certificates {

	/**
	 * Given a certificate, extract the public key for operations such as encryption/signature
	 */
	
	/**
	 * Client side public key methods
	 * @param certfile
	 * @return
	 * @throws UnsupportedEncodingException 
	 * @throws CertificateException 
	 * @throws FileNotFoundException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static PublicKey getPublicKey(String data) throws CertificateException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		String cer = data;
		FileInputStream fileInputStream = new FileInputStream(cer);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)cf.generateCertificate(fileInputStream);
		PublicKey publicKey = cert.getPublicKey();
		byte[] encoded = publicKey.getEncoded();
		byte[] b64key = Base64.getEncoder().encode(encoded);
		//System.out.println("b64key = " + new String(b64key));

		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey key = keyFactory.generatePublic(x509EncodedKeySpec);

		//System.out.println();
		//System.out.println("x509EncodedKeySpec = " + new String(key.getEncoded()));
		
		return publicKey;
	}

}
