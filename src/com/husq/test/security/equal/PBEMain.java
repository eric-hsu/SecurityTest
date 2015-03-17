package com.husq.test.security.equal;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PBEMain {
	private static String str = "husq PBE test";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkPBE();
		bcPBE();
	}

	public static void jdkPBE(){
		try{
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);
			
			//口令和密码
			String password = "husq";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("jdk pbe encrypt="+Hex.encodeHexString(result));
			
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			byte[] dsign = cipher.doFinal(result);
			System.out.println("jdk pbe dncrypt="+new String(dsign));
			System.out.println("==========================================");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		
	}
	
	public static void bcPBE(){
		
		try{
			Security.addProvider(new BouncyCastleProvider());
			
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);
			
			//口令和密码
			String password = "husq";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES","BC");
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("bc pbe encrypt="+Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			byte[] dsign = cipher.doFinal(result);
			System.out.println("bc pbe dncrypt="+new String(dsign));
			
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}
}
