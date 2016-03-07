package com.husq.test.security.uequal;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSAMain {
	private static String str= "husq RSA test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		jdkRSA();
	}
	
	public static void jdkRSA(){
		try{
			
			BASE64Encoder encoder = new BASE64Encoder();
			BASE64Decoder decoder = new BASE64Decoder();
	
			//1 初始化秘钥
//			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//			keyPairGenerator.initialize(512);
//			KeyPair keyPair = keyPairGenerator.generateKeyPair();
//			RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
//			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
//			System.out.println("public key : "+ Base64.encodeBase64String(rsaPublicKey.getEncoded()));
//			System.out.println("private key : "+ Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
			
			
			//2 私钥加密，公钥解密---加密
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decoder.decodeBuffer(getServerPrivateKey()));
			KeyFactory kFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("私钥加密，公钥解密---加密 :"+ Base64.encodeBase64String(result));
			
			
			//3,私钥加密，公钥解密--解密
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decoder.decodeBuffer(getServerPublicKey()));
			kFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			result = cipher.doFinal(result);
			System.out.println("私钥加密，公钥解密---解密："+ new String(result));
			
			//4,公钥加密，私钥解密--加密
			x509EncodedKeySpec  = new X509EncodedKeySpec(decoder.decodeBuffer(getServerPublicKey()));
			kFactory = KeyFactory.getInstance("RSA");
			publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(str.getBytes());
			System.out.println("公钥加密，私钥解密---加密："+Base64.encodeBase64String(result));
			
			//5,公钥加密，私钥解密--解密
			pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decoder.decodeBuffer(getServerPrivateKey()));
			kFactory = KeyFactory.getInstance("RSA");
			privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			result = cipher.doFinal(result);
			System.out.println("公钥加密，私钥解密---解密："+new String(result));
			
			
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	
	public static String getServerPrivateKey() throws IOException{

		String serverPrivateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMA0sHIC5sJd4Lmm"+
"QHz3y5hKzI/rYYINSA4RqhRmprrizyKnslIwaV96uG8U3CZFuo80/DOcAy/voHZS"+
"3m50S8+cXmGeJGMouDMHhF78iFczvdwYRwbxYIEU9mMO2V2IaaXaBVmoYtaK+0ni"+
"gMCu6p0vPuw4Fe8nGeObPdU5BXGdAgMBAAECgYAnprb/zjlsv5Esu29yWGxX7pZk"+
"2lozSiojPOGpc8PRqhixPYc8DWCvodGKmPMRsjDaekPNIdJGgVjJEC9y+erpfUEy"+
"ZR4hYw2xxlAZQYJANb3Z9G0U7y91pYKAYFouG2SxSuc4iNnN0h5X/5YtAjZvctPh"+
"dCt9S3arZPIPNStcAQJBAPw73qInQ9vv4EELrOma6wZmutDaEk5QqHlgdiAARytJ"+
"0nqH0uoytQkzNt2FH+Z1OZcqGIbMa2y5dW6bSWE9QM0CQQDDE17QDMDBItEIeyCf"+
"ldXCITWIuz6hKTQB1NRW3akxcf197Y5QxpMxkfTDRoX2vvn9NNwF3thsvoVIQJyr"+
"9LQRAkBdgDwJVBDdqNAyjIdumVTiLJa38P60NUYeqFlhh3jaXSU+8raGxoFBhdCi"+
"0USAA5hzptEstv5jcWRMuhe7ih9JAkAfDrxvnzgpB6QEF6ZQAgjwSV0+kaEdA3RW"+
"Pk44Lj47swxKukGINrVElRpE5Lt7V1hxqbLF9H68gXCy2iaXcfQhAkBxgheRboQn"+
"ZImljsqx0DcXxX0DGGnzQ2FZPefon8jz2UH2HfDPyZH2AfhC28NQ4xJs6kW0CWbe"+
"B9CHgsaKe8Pj";
		
		return serverPrivateKey;
	}
	
	public static String getServerPublicKey() throws IOException{

		String serverPublickey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDANLByAubCXeC5pkB898uYSsyP"+
"62GCDUgOEaoUZqa64s8ip7JSMGlferhvFNwmRbqPNPwznAMv76B2Ut5udEvPnF5h"+
"niRjKLgzB4Re/IhXM73cGEcG8WCBFPZjDtldiGml2gVZqGLWivtJ4oDAruqdLz7s"+
"OBXvJxnjmz3VOQVxnQIDAQAB";
		
		return serverPublickey;
	}
	
}
