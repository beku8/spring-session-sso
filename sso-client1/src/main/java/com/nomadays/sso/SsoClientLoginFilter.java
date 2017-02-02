package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * To handle login request from client app.
 * So on the UI, you can set this url (/sso-login).
 * 
 * Should be placed somewhere in the security filter chain. e.g before {@link UsernamePasswordAuthenticationFilter}
 * @author beku
 *
 */
public class SsoClientLoginFilter extends OncePerRequestFilter {
	
	private AuthenticationEntryPoint authenticationEntryPoint;
	
	// /login causes issues. So needs to use different path instead
	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/sso-login");

	public SsoClientLoginFilter(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (requestMatcher.matches(request)) {
			SecurityContext securityContext = SecurityContextHolder.getContext();
			if (securityContext.getAuthentication() == null || !securityContext.getAuthentication().isAuthenticated()) {
				authenticationEntryPoint.commence(request, response, new NullAuthenticationException());
				return;
			}
		} 
		filterChain.doFilter(request, response);
	}
	
	public static class NullAuthenticationException extends AuthenticationException {

		private static final long serialVersionUID = 1L;

		public NullAuthenticationException() {
			super("SSO client login request detected");
		}
		
	}

}
