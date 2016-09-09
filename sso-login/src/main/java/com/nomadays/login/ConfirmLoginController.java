package com.nomadays.login;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nomadays.sso.SsoServerSettings;

@RestController
public class ConfirmLoginController {
	
	@Autowired SsoServerSettings ssoServerSettings;
	
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@RequestMapping("/confirmLogin")
	public void getSession(HttpSession session, @RequestParam("redirect") String redirect,
				HttpServletRequest request, HttpServletResponse response) throws IOException {
		if (ssoServerSettings.allow(redirect)) {
			redirectStrategy.sendRedirect(request, response, redirect + "?token=" + session.getId());
		}
		else {
			throw new AccessDeniedException("Illegal redirect uri");
		}
		
	}
}
