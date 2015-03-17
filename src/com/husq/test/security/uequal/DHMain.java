package com.husq.test.security.uequal;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.apache.commons.codec.binary.Hex;
import com.sun.org.apache.xalan.internal.utils.Objects;

//非对称算法DH
public class DHMain {
	private static String str="husq DH test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		jdkDH();
	}
	
	
	public static void jdkDH(){
		try{
			//1 初始化秘钥
			KeyPairGenerator senderkeyPairGenerator = KeyPairGenerator.getInstance("DH");
			senderkeyPairGenerator.initialize(512);
			KeyPair senderKeyPair = senderkeyPairGenerator.generateKeyPair();
			byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();//发送方秘钥，发送给接收方（网络，文件）
			
			//2 初始化接收方秘钥
			KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);
			PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
			
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			KeyPair receiverKeyPair =receiverKeyPairGenerator.generateKeyPair();
			PrivateKey privateKey = receiverKeyPair.getPrivate();
			byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();
			
			//3 秘钥构建
			KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(privateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");
			
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
			PublicKey senderPublicKey =senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderKeyPair.getPrivate());
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
			if(Objects.equals(receiverDesKey, senderDesKey)){
				System.out.println("双方秘钥相同");
			}
			
			//4 加密
			Cipher  cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("jdk dh encrypt: "+Hex.encodeHexString(result));
			
			
			//5 解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			byte[] nsign = cipher.doFinal(result);
			System.out.println("jdk dh decrypt: "+new String(nsign));
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
