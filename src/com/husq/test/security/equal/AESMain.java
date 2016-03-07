package com.husq.test.security.equal;

import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AESMain {
	private static String str = "husq AES test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkAES();
		bcAES();
	}

	public static void jdkAES(){
		
		try{
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey  securetkey = keyGenerator.generateKey();
			byte[] keyBytes = securetkey.getEncoded();
			
			String aesKey = (new BASE64Encoder()).encodeBuffer(keyBytes);
			System.out.println("AES密钥，aesKey:"+aesKey);
			//key转换
			Key key = new SecretKeySpec((new BASE64Decoder()).decodeBuffer(aesKey) ,"AES");
			
			//加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(str.getBytes());
			
			System.out.println("jdk AES encrypt="+Hex.encodeHexString(result));
			
			
			//解密
			Key keyDncrypt = new SecretKeySpec((new BASE64Decoder()).decodeBuffer(aesKey),"AES");
			cipher.init(Cipher.DECRYPT_MODE, keyDncrypt);
			byte[] dsign  = cipher.doFinal(result);
			System.out.println("jdk AES dncrypt="+new String(dsign));
			
			System.out.println("==========================================");
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}
	
	
	public static void bcAES(){
		
		try{
			Security.addProvider(new BouncyCastleProvider());
			
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
			keyGenerator.getProvider();
			keyGenerator.init(128);
			SecretKey  securetkey = keyGenerator.generateKey();
			byte[] keyBytes = securetkey.getEncoded();
			
			//key转换
			Key key = new SecretKeySpec(keyBytes,"AES");
			
			//加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(str.getBytes());
			
			System.out.println("bc AES encrypt="+Hex.encodeHexString(result));
			
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] dsign  = cipher.doFinal(result);
			System.out.println("bc AES dncrypt="+new String(dsign));
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
