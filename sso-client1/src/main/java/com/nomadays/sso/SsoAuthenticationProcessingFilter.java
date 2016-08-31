package com.nomadays.sso;

import java.io.IOException;

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
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

public class SsoAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	private SessionRepository<Session> sessionRepository;
	
	public final String TOKEN_PARAM = "token";

	@SuppressWarnings("unchecked")
	public <S extends Session> SsoAuthenticationProcessingFilter(SessionRepository<S> sessionRepository) {
		super(new AntPathRequestMatcher("/login_callback"));
		this.sessionRepository = (SessionRepository<Session>) sessionRepository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		
		String sessionId = request.getParameter(TOKEN_PARAM);
		if(sessionId != null){
			Session session = sessionRepository.getSession(sessionId);
			if(session != null){
				SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
				logger.debug("session {}", securityContext.getAuthentication());
				logger.debug("authentication manager {}", this.getAuthenticationManager());
				
				
				response.addCookie(new Cookie("SESSION", sessionId));
				return securityContext.getAuthentication();
			}
		}
		 
		return null;
	}

}
