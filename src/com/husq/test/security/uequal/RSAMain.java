package com.husq.test.security.uequal;

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
			//1 初始化秘钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
			System.out.println("public key : "+ Base64.encodeBase64String(rsaPublicKey.getEncoded()));
			System.out.println("private key : "+ Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
			
			//2 私钥加密，公钥解密---加密
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			KeyFactory kFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("私钥加密，公钥解密---加密 :"+ Base64.encodeBase64String(result));
			
			
			//3,私钥加密，公钥解密--解密
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			kFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			result = cipher.doFinal(result);
			System.out.println("私钥加密，公钥解密---解密："+ new String(result));
			
			//4,公钥加密，私钥解密--加密
			x509EncodedKeySpec  = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			kFactory = KeyFactory.getInstance("RSA");
			publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(str.getBytes());
			System.out.println("公钥加密，私钥解密---加密："+Base64.encodeBase64String(result));
			
			//5,公钥加密，私钥解密--解密
			pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			kFactory = KeyFactory.getInstance("RSA");
			privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			cipher.doFinal(result);
			System.out.println("公钥加密，私钥解密---解密："+new String(result));
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
