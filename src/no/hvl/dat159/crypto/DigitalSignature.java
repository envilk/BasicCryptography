/**
 * 
 */
package no.hvl.dat159.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.xml.bind.DatatypeConverter;

/**
 * @author tdoy
 *
 */
public class DigitalSignature {
	
	public static final String SIGNATURE_SHA256WithDSA = "SHA256WithDSA";
	public static final String SIGNATURE_SHA256WithRSA = "SHA256WithRSA";
	
	public static byte[] sign(String message, PrivateKey privateKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
		
		Signature sign = Signature.getInstance(algorithm);
		
		sign.initSign(privateKey);
		
		byte[] m = message.getBytes();      

		sign.update(m);
		
		byte[] signature = sign.sign();
		
		return signature;
		
	}
	
	public static boolean verify(String message, byte[] digitalSignature, PublicKey publickey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
		
		Signature sign = Signature.getInstance(algorithm);
		
		sign.initVerify(publickey);
		
		byte[] m = message.getBytes();
		
		sign.update(m);
		
		boolean bool = sign.verify(digitalSignature);
		
		return bool;
	}
	
	public static String getHexValue(byte[] signature) {
		
		return DatatypeConverter.printHexBinary(signature);
	}
	
	public static byte[] getEncodedBinary(String signatureinhex) {
		
		return DatatypeConverter.parseHexBinary(signatureinhex);
	}

}
