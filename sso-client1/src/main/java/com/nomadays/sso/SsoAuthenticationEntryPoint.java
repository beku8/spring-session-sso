package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

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
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		// login uri should be in external configuration.
		String loginUri = "http://localhost:8080"; 
		SsoRedirection.redirectConfirmLogin(request, response, loginUri);
	}

}
