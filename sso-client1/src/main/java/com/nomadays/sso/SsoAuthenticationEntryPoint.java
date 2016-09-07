package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

public class SsoAuthenticationEntryPoint implements AuthenticationEntryPoint {
	
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		String scheme = request.getScheme();
		String host = request.getServerName();
		Integer port = request.getServerPort();
		String callbackDomain = String.format("%s://%s", scheme, host);
		if (port != 80) {
			callbackDomain += ":" + port;
		}
		String loginDomain = "http://localhost:8080";
		redirectStrategy.sendRedirect(request, response, String.format("%s/confirmLogin?redirect=%s/login_callback", loginDomain, callbackDomain));
	}

}
