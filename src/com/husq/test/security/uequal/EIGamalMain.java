package com.husq.test.security.uequal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EIGamalMain {
	private static String str= "husq EIGamal test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		bcEIGamal();
	}
	
	public static void bcEIGamal(){
		try{
			Security.addProvider(new BouncyCastleProvider());
			
			//1 初始化秘钥
			AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
			algorithmParameterGenerator.init(256);
			AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
			DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
			
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
			keyPairGenerator.initialize(dhParameterSpec,new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey elGamalPublicKey = keyPair.getPublic();
			PrivateKey elGamalPrivateKey = keyPair.getPrivate();
			System.out.println("public key : "+ Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
			System.out.println("private key : "+ Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
			
			//2 私钥加密，公钥解密---加密
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
			KeyFactory kFactory = KeyFactory.getInstance("ElGamal");
			PrivateKey privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			Cipher cipher = Cipher.getInstance("ElGamal");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("私钥加密，公钥解密---加密 :"+ Base64.encodeBase64String(result));
			
			
			//3,私钥加密，公钥解密--解密
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
			kFactory = KeyFactory.getInstance("ElGamal");
			PublicKey publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("ElGamal");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			result = cipher.doFinal(result);
			System.out.println("私钥加密，公钥解密---解密："+ new String(result));
			
			//4,公钥加密，私钥解密--加密
			x509EncodedKeySpec  = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
			kFactory = KeyFactory.getInstance("ElGamal");
			publicKey = kFactory.generatePublic(x509EncodedKeySpec);
			cipher = Cipher.getInstance("ElGamal");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(str.getBytes());
			System.out.println("公钥加密，私钥解密---加密："+Base64.encodeBase64String(result));
			
			//5,公钥加密，私钥解密--解密
			pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
			kFactory = KeyFactory.getInstance("ElGamal");
			privateKey = kFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance("ElGamal");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			cipher.doFinal(result);
			System.out.println("公钥加密，私钥解密---解密："+new String(result));
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
