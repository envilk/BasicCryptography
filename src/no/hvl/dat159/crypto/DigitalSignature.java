/**
 * 
 */
package no.hvl.dat159.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

/**
 * @author tdoy
 *
 */
public class DigitalSignature {

	//public static final String SIGNATURE_SHA256WithDSA = "SHA256WithDSA";
	public static final String SIGNATURE_SHA256WithRSA = "SHA256WithRSA";

	public static byte[] sign(String message, PrivateKey privateKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException, NoSuchProviderException {

		Signature sign = Signature.getInstance(algorithm, "SunRsaSign");

		sign.initSign(privateKey);
		
		byte[] dataBytes = message.getBytes();

		sign.update(dataBytes);

		byte[] signature = sign.sign();

		return signature;

	}

	public static boolean verify(String message, byte[] digitalSignature, PublicKey publickey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException, NoSuchProviderException {

		Signature sign = Signature.getInstance(algorithm, "SunRsaSign");

		sign.initVerify(publickey);
		
		byte[] dataBytes = message.getBytes();

		//byte[] dataBytes = Base64.getEncoder().encode(message.getBytes());
		//dataBytes = Base64.getDecoder().decode(dataBytes);

		sign.update(dataBytes);

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
