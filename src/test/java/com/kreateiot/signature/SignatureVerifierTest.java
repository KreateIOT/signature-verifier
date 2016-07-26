package com.kreateiot.signature;

import org.junit.Assert;
import org.junit.Test;

public class SignatureVerifierTest {
	
	@Test
	public void testSignature() throws Exception {
		String signature = SignatureVerifier.signature("healthwizz", "fitbit", "niteen", "20160724160200", "CONNECT", "QOge0mFXxpyQBQl4uBtZcKTDrj4ozXcmvfZHIkP1FdMZIXGNokLBGsTTKddF");
		Assert.assertNotNull(signature);
	}
	
}