package com.husq.test.security.equal;

import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


//3DES 速度慢
public class DES3Main {
	private static String str= "husq DES test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdk3DES();
		bc3DES();
	}
	//jdk DES
	public static void jdk3DES(){
			try{
				//生成key
				KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
				keyGenerator.init(168);
				SecretKey secretKey = keyGenerator.generateKey();
				byte[] byteKey = secretKey.getEncoded();
				
				//key转换
				DESKeySpec desKeySpec = new DESKeySpec(byteKey);
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				Key convertSecretKey = factory.generateSecret(desKeySpec);
				
				//加密
				Cipher  cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
				byte[] result = cipher.doFinal(str.getBytes());
				System.out.println("jdk 3des encrypt="+Hex.encodeHexString(result));
				
				//解密
				cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
				byte[] dsign = cipher.doFinal(result);
				
				System.out.println("jdk 3des decrypt="+new String(dsign));
				
				System.out.println("==========================================");
			}catch(Exception e){
				e.printStackTrace();
			}
			
			
		}
		
		//bcprov-jdk15-133.jar DES
		public static void bc3DES(){
			try{
				Security.addProvider(new BouncyCastleProvider());
				
				//生成key
				KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
				keyGenerator.getProvider();
				keyGenerator.init(168);
				SecretKey secretKey = keyGenerator.generateKey();
				byte[] byteKey = secretKey.getEncoded();
				
				//key转换
				DESKeySpec desKeySpec = new DESKeySpec(byteKey);
				SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
				Key convertSecretKey = factory.generateSecret(desKeySpec);
				
				//加密
				Cipher  cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
				byte[] result = cipher.doFinal(str.getBytes());
				System.out.println("bc 3des encrypt="+Hex.encodeHexString(result));
				
				
				//解密
				cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
				byte[] dsign = cipher.doFinal(result);
				
				System.out.println("bc 3des decrypt="+new String(dsign));
			}catch(Exception e){
				e.printStackTrace();
			}
			
		}
}
