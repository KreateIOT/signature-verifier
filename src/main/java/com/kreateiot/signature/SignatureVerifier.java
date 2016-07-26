package com.kreateiot.signature;

import static org.apache.commons.codec.digest.HmacUtils.hmacSha256;
import static org.apache.commons.codec.digest.HmacUtils.hmacSha256Hex;
import static org.apache.commons.lang3.StringUtils.isEmpty;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

//
// KIOT_SIGNATURE = HexEncode(HMAC(SIGNING_KEY, SECURE_DATA))
//
// SIGNING_KEY = HMAC(HMAC(HMAC("KIOT" + KIOT_SECRET_KEY, YYYYMMDD), KIOT_CLIENT_ID), "KIOT_REQUEST")

// HMAC-SHA256
// COMMAND
// YYYYMMddHHmmss
// KreateIoTDeviceID:UTCTimestampInYYYYMMddHHmmssFormat:APIConsumerGeneratedUserID
// KreateIoTClientID
public class SignatureVerifier {
	
	private static final SimpleDateFormat sdf = new SimpleDateFormat("YYYYMMddHHmmss");
	
	static {
		sdf.setLenient(false);
	}
	
	private static Logger logger = LogManager.getLogger(SignatureVerifier.class);
	
	public static boolean validate(String clientId, String deviceId, String signature, 
			String userId, String timestamp, String command, String secret) throws InvalidSignatureException {
		//validate all parameters are non-null, non-empty
		if (isEmpty(clientId) || isEmpty(deviceId) || isEmpty(signature) || 
				isEmpty(userId) || isEmpty(timestamp) || isEmpty(command) || isEmpty(secret)) {
			logger.debug("Can not verify as one of the required parameters is null or empty");
			throw new InvalidSignatureException();
		}
		
		//validate timestamp
		validateTimestamp(timestamp);
		
		try {
			if (signature.equals(signature(clientId, deviceId, userId, timestamp, command, secret))) return true;
		} catch (UnsupportedEncodingException e) {
			logger.fatal("CHECK SYSTEM SETTINGS. UNABLE TO ENCODE HMAC-SHA256");
		}
		
		return false;
	}
	
	public static String signature(String clientId, String deviceId, 
			String userId, String timestamp, String command, String secret) throws UnsupportedEncodingException {
		StringBuilder builder = new StringBuilder("HMAC-SHA256\n");
		builder.append(command).append('\n')
				.append(timestamp).append('\n')
				.append(deviceId).append(':').append(timestamp).append(':').append(userId).append('\n')
				.append(clientId);
		return hmacSha256Hex(signingKey(clientId, secret, timestamp), builder.toString().getBytes("UTF-8"));
	}
	
	protected static byte[] signingKey(String clientId, String secret, String timestamp) throws UnsupportedEncodingException {
		return hmacSha256(
				hmacSha256(
						hmacSha256(("KIOT" + secret).getBytes("UTF-8"), timestamp.getBytes("UTF-8")), 
						clientId.getBytes("UTF-8")), 
				"KIOT_REQUEST".getBytes("UTF-8"));
	}
	
	private static void validateTimestamp(String timestamp) throws InvalidSignatureException {
		try {
			sdf.parse(timestamp);
		} catch (ParseException | NullPointerException e) {
			logger.error("Unable to parse timestamp {}. Timestamp in format YYYYMMddHHmmss.", timestamp);
			throw new InvalidSignatureException();
		}
	}

}
