package com.nomadays.sso;

import static org.junit.Assert.*;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class SsoServerSettingsTest {

	@Test
	public void test() throws MalformedURLException {
		List<String> uris = new ArrayList<>();
		uris.add("http://beku-laptop:9090/");
		uris.add("https://www.google.com");
		
		SsoServerSettings ssoServerSettings = new SsoServerSettings();
		ssoServerSettings.setAllowedUris(uris);
		
		assertTrue(ssoServerSettings.allow("http://beku-laptop:9090"));
		assertTrue(ssoServerSettings.allow("http://beku-laptop:9090/login_callback?session=12345"));
		
		assertFalse(ssoServerSettings.allow("https://google.com"));
		assertFalse(ssoServerSettings.allow("google.com"));
	}

}
