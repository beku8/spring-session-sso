package com.nomadays.sso;

import java.util.List;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("sso.server")
public class SsoServerSettings {
	
	private List<String> allowedUris = new ArrayList<>();
	
	public List<String> getAllowedUris() {
		return allowedUris;
	}

	public void setAllowedUris(List<String> allowedUris) {
		this.allowedUris = allowedUris;
	}

	
	public boolean allow(String uri){
		for(String allowedUri: this.allowedUris){
			try {
				URL allowedUrl = new URL(allowedUri);
				URL url = new URL(uri);
				
				if (allowedUrl.getProtocol().equals(url.getProtocol()) &&
					allowedUrl.getHost().equals(url.getHost()) &&
					allowedUrl.getPort() == url.getPort()) {
					return true;
				}
				
			} catch (MalformedURLException e) {
				
			}
		}
		
		return false;
	}



}
