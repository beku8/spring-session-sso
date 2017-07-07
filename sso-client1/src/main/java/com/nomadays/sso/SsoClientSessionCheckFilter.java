package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.filter.OncePerRequestFilter;

public class SsoClientSessionCheckFilter extends OncePerRequestFilter {
  
  private Logger logger = LoggerFactory.getLogger(getClass());
  
  public static final String SESSION_SYNCHRONIZED = "SSO_SESSION_SYNCHRONIZED";

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
 // login uri should be in external configuration.
    String loginUri = "http://localhost:8080"; 
    
    HttpSession session = request.getSession(false);
    if (session != null) {
      logger.debug("session maxInactiveInterval {}", session.getMaxInactiveInterval());
      SecurityContext securityContext = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
      Boolean sessionConfirmed = (Boolean) session.getAttribute(SESSION_SYNCHRONIZED);
      if (securityContext == null && (sessionConfirmed == null || !sessionConfirmed)) {
        logger.debug("Synchronizing anonymous user session {}", session.getId());
        SsoRedirection.redirectConfirmSession(request, response, loginUri);
        return;
      }
    } else {
      SsoRedirection.redirectConfirmSession(request, response, loginUri);
      return;
    }
    chain.doFilter(request, response);
  }

}
