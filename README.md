# Description #
Validates signature using
	
	KIOT_SIGNATURE = HexEncode(HMAC(SIGNING_KEY, SECURE_DATA))

Where 
	
	SIGNING_KEY = HMAC(HMAC(HMAC("KIOT" + KIOT_SECRET_KEY, YYYYMMDD), KIOT_CLIENT_ID), "KIOT_REQUEST")

And Secure Data is
	
	HMAC-SHA256
	COMMAND
	YYYYMMddHHmmss
	KreateIoTDeviceID:UTCTimestampInYYYYMMddHHmmssFormat:APIConsumerGeneratedUserID
	
Provides methods 
	
	validate(String clientId, String deviceId, String signature, String userId, String timestamp, String command, String secret)
	
and 
	
	signature(String clientId, String deviceId, String userId, String timestamp, String command, String secret)
	
# Gradle #
 	
 	repositories {
	    jcenter()
	}
	
	dependencies {
		compile 'com.kreateiot:signature-verifier:1.0.0'
	}