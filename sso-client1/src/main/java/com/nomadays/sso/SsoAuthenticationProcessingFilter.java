package com.nomadays.sso;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.ExpiringSession;
import org.springframework.session.SessionRepository;

public class SsoAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	private SessionRepository<ExpiringSession> sessionRepository;
	
	public final String TOKEN_PARAM = "token";

	@SuppressWarnings("unchecked")
	public <S extends ExpiringSession> SsoAuthenticationProcessingFilter(SessionRepository<S> sessionRepository) {
		super(new AntPathRequestMatcher("/login_callback"));
		this.sessionRepository = (SessionRepository<ExpiringSession>) sessionRepository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		
		String sessionId = request.getParameter(TOKEN_PARAM);
		if(sessionId != null){
			ExpiringSession session = sessionRepository.getSession(sessionId);
			if(session != null){
				SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
				logger.debug("session {}", securityContext.getAuthentication());
				logger.debug("authentication manager {}", this.getAuthenticationManager());
				
				Long expiryInMilliSeconds = session.getCreationTime() + session.getMaxInactiveIntervalInSeconds() * 1000;
				
				
				Long maxAge = (new Date().getTime() - expiryInMilliSeconds)/1000;
				logger.debug("maxAge {}", maxAge.toString());
				Cookie cookie = new Cookie("SESSION", sessionId);
				cookie.setMaxAge(Integer.parseInt(maxAge.toString()));
				response.addCookie(cookie);
				return securityContext.getAuthentication();
			}
		}
		 
		return null;
	}

}
