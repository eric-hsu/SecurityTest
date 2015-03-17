package com.husq.test.security;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class BASE64Main {

	private static String str = "husq security base64";
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkBase64();
		commonsCodec();
		bcprovCastleBase64();
	}
	
	//jdk
	public static void jdkBase64(){
		try{
			BASE64Encoder encoder = new BASE64Encoder();
			String encoderstr = encoder.encode(str.getBytes());
			System.out.println("jdk encoderstr="+encoderstr);
			BASE64Decoder decoder = new BASE64Decoder();
			String decoderstr = new String(decoder.decodeBuffer(encoderstr));
			System.out.println("jdk decoderstr="+decoderstr);
			System.out.println();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	//commons-codec-1.2.jar
	public static void commonsCodec(){
		byte[] encodeBytes = Base64.encodeBase64(str.getBytes());
		System.out.println("commons-codec encodeBytes="+new String(encodeBytes));
		byte[] decodeBytes = Base64.decodeBase64(encodeBytes);
		System.out.println("commons-codec decodeBytes="+new String(decodeBytes));
		System.out.println();
	}
	
	//bcprov-jdk15-133.jar
	public static void bcprovCastleBase64(){
		byte[] encodeBytes = org.bouncycastle.util.encoders.Base64.encode(str.getBytes());
		System.out.println("bcprov-jdk15-133 encodeBytes="+new String(encodeBytes));
		byte[] decodeBytes = org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
		System.out.println("bcprov-jdk15-133 decodeBytes="+new String(decodeBytes));
		System.out.println();
	}
}
