package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class ConfirmSessionFilter extends OncePerRequestFilter {
  
  public static final String SESSION_SYNCHRONIZED = "SSO_SESSION_SYNCHRONIZED";
  
  private Logger logger = LoggerFactory.getLogger(getClass());
  private static final int THIRTY_DAYS_SECONDS = 2592000;
  private int validitySeconds = THIRTY_DAYS_SECONDS;
  
  private RequestMatcher requestMatcher = new AntPathRequestMatcher("/confirm_session");
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  
  private SsoServerSettings ssoServerSettings;
  
  public ConfirmSessionFilter(SsoServerSettings ssoServerSettings) {
    this.ssoServerSettings = ssoServerSettings;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    //TODO check for allowed uris.
    String redirect = request.getParameter("redirect");
    if (requestMatcher.matches(request) && redirect != null && ssoServerSettings.allow(redirect)) {
      SecurityContext securityContext = SecurityContextHolder.getContext();
      HttpSession session = request.getSession(true);
      if ("anonymousUser".equals(securityContext.getAuthentication().getPrincipal())) {
        Boolean sessionConfirmed = (Boolean) session.getAttribute(SESSION_SYNCHRONIZED);
        if (sessionConfirmed == null || !sessionConfirmed) {
          session.setAttribute(SESSION_SYNCHRONIZED, true);
          session.setMaxInactiveInterval(validitySeconds);
          logger.debug("Anonymous user session synchronized {}", session.getId());
        }
      }
      String targetUrl = redirect + "&token=" + ConfirmLoginController.encryptAndEncode(session.getId());
      logger.debug("redirecting to {}", targetUrl);
      redirectStrategy.sendRedirect(request, response, targetUrl);
      return;
    }
    chain.doFilter(request, response);
  }

  public void setValiditySeconds(int validitySeconds) {
    this.validitySeconds = validitySeconds;
  }
  

}
