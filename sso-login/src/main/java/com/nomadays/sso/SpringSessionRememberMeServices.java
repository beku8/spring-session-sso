package com.nomadays.sso;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;

public class SpringSessionRememberMeServices implements RememberMeServices {
	
	private int maxAge = 60 * 60 * 24 * 30;
	
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

	@Override
	public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
		int interval = 60 * 60 * 24 * 30;
		System.out.print("setting interval " + interval);
		request.getSession().setMaxInactiveInterval(interval);
	}

	public int getMaxAge() {
		return maxAge;
	}

	public void setMaxAge(int maxAge) {
		this.maxAge = maxAge;
	}
	
	
	

}
