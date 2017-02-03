package com.nomadays.sso;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.ExpiringSession;
import org.springframework.session.SessionRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter to ensure the authentication.
 * Registers on /login_callback url, and checks the returned token from Login server.
 * if the Session is valid and exists, it simply sets the 'SESSION' cookie same as the login server & redirects.
 * 
 * @author beku
 *
 */
public class SsoClientLoginCallbackFilter extends OncePerRequestFilter {
	
	public final String TOKEN_PARAM = "token";
	private String defaultTargetUrl = "/";
	
	private SessionRepository<ExpiringSession> sessionRepository;
	private RequestCache requestCache;
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/login_callback");
	
	@SuppressWarnings("unchecked")
	public <S extends ExpiringSession> SsoClientLoginCallbackFilter(SessionRepository<S> sessionRepository, RequestCache requestCache) {
		this.sessionRepository = (SessionRepository<ExpiringSession>) sessionRepository;
		this.requestCache = requestCache;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (requestMatcher.matches(request)) {
			String token = request.getParameter(TOKEN_PARAM);
			if(token != null){
				String sessionId = decodeAndDecrypt(token);
				ExpiringSession session = sessionRepository.getSession(sessionId);
				SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
				if(session != null && securityContext.getAuthentication().isAuthenticated()){
					logger.debug("found valid session {}", session);
					Long expiryInMilliSeconds = new Long(session.getMaxInactiveIntervalInSeconds()) * 1000 + session.getCreationTime();
					Long maxAge = (expiryInMilliSeconds - new Date().getTime())/1000;
					Cookie cookie = new Cookie("SESSION", sessionId);
					cookie.setMaxAge(Integer.parseInt(maxAge.toString()));
					response.addCookie(cookie);
					
					String targetUrl = defaultTargetUrl;
					SavedRequest savedRequest = requestCache.getRequest(request, response);
					if (savedRequest != null) {
						logger.debug("re-enforcing cached request at {} {}", savedRequest.getRedirectUrl(), savedRequest.getMethod());
						// inspired from HttpSessionRequestCache
						session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
						sessionRepository.save(session);
						targetUrl = savedRequest.getRedirectUrl();
					} 
					redirectStrategy.sendRedirect(request, response, targetUrl);
					return;
				}
			}
		}
		filterChain.doFilter(request, response);
	}
	
	private String decodeAndDecrypt(String token){
		try {
			// decode
			byte[] decoded = Base64.getUrlDecoder().decode(token);
			
			String key = "G~Y@86-FtH&gq'_e"; // 128 bit key, better be handled in external properties
			// Create key and cipher
			Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			// Decrypt
			cipher.init(Cipher.DECRYPT_MODE, aesKey);
            String decrypted = new String(cipher.doFinal(decoded));
            return decrypted;
		
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException e) {
			
		} 
		return null;
	}

}
