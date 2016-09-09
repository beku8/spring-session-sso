package com.nomadays.sso;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.session.web.http.CookieSerializer;

/**
 * 
 * {@link RememberMeServices}'s implementation that just has a long lived session.
 * 
 * This is ok to do that, because all the session objects are loaded to redis or some external storage.
 * Main reason default spring security's RememberMeServices uses a token is that it doesn't want to keep
 * the expired seasons, which would overload the server. 
 * 
 * This class has to be configured with {@link CookieSerializer} that takes care of setting the cookie expiry.
 * Since this class will only take care of the session.
 * 
 * @author beku
 *
 */
public class SpringSessionRememberMeServices implements RememberMeServices {
	
	private int maxAge = 60 * 60 * 24 * 30; // 30 days of maxAge by default
	
	public SpringSessionRememberMeServices() {}
	
	public SpringSessionRememberMeServices(int maxAge) {
		this.maxAge = maxAge;
	}
	
	@Override
	public Authentication autoLogin(HttpServletRequest arg0, HttpServletResponse arg1) {
		return null;
	}

	@Override
	public void loginFail(HttpServletRequest arg0, HttpServletResponse arg1) {

	}

	/* 
	 * This implementation will always extend the session live time. 
	 * Regardless of whether 'remember me' checked or not from the login form.
	 * 
	 * You can configure here to consider the 'remember me' checkbox here. 
	 * 
	 * (non-Javadoc)
	 * @see org.springframework.security.web.authentication.RememberMeServices#loginSuccess(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.springframework.security.core.Authentication)
	 */
	@Override
	public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
		request.getSession().setMaxInactiveInterval(this.maxAge);
	}

	public int getMaxAge() {
		return maxAge;
	}

	public void setMaxAge(int maxAge) {
		this.maxAge = maxAge;
	}
	
	
	

}
