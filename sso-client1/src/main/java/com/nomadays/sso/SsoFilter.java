package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.web.filter.OncePerRequestFilter;

public class SsoFilter extends OncePerRequestFilter {
	
	private SessionRepository<Session> sessionRepository;

	private Logger logger = LoggerFactory.getLogger(getClass());
	private RequestMatcher matcher = new AntPathRequestMatcher("/login_callback");
	
	
	
	@SuppressWarnings("unchecked")
	public <S extends Session> SsoFilter(SessionRepository<S> sessionRepository) {
		super();
		this.sessionRepository = (SessionRepository<Session>) sessionRepository;
	}


//
//	public SsoFilter(RedisOperationsSessionRepository sessionRepository) {
//		super();
//		this.sessionRepository = sessionRepository;
//	}



	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("chaining filter");
		if(matcher.matches(request)){
			String token = request.getParameter("token");
			if(token != null){
				logger.debug("token {}", token);
				Session session = sessionRepository.getSession(token);
				if(session != null){
					for(String key : session.getAttributeNames()) {
						logger.debug("ATTR {}", key);
					}
					SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
					logger.debug("session {}", securityContext.getAuthentication());
				}
			}
		}
		
		filterChain.doFilter(request, response);

	}

}
