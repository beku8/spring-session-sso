package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

/**
 * 
 * This entry point will redirect to the Login server on {@link AuthenticationException}.
 * Must configure it at exception handling: 

	.and()
		.exceptionHandling()
			.authenticationEntryPoint(ssoAuthenticationEntryPoint())
			
 * 
 * @author beku
 *
 */
public class SsoAuthenticationEntryPoint implements AuthenticationEntryPoint {
	
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		// TODO should check for X-Forwared headers, in case of working behind proxy.
		String scheme = request.getScheme();
		String host = request.getServerName();
		Integer port = request.getServerPort();
		String callbackUri = String.format("%s://%s", scheme, host);
		if (port != 80) {
			callbackUri += ":" + port;
		}
		// login uri should be in external configuration.
		String loginUri = "http://localhost:8080"; 
		
		String uri = String.format("%s/confirm_login?redirect=%s/login_callback", loginUri, callbackUri);
		logger.debug("redirecting to {}", uri);
		redirectStrategy.sendRedirect(request, response, uri);
	}

}
