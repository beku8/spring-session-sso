package com.nomadays.sso;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

public class SsoRedirection {
  
  private final static RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
  private static Logger logger = LoggerFactory.getLogger(SsoRedirection.class);
  
  public static void redirectConfirmLogin(HttpServletRequest request, HttpServletResponse response, String loginUri) throws IOException {
    String uri = String.format("%s/confirm_login?redirect=%s/login_callback", loginUri, getCurrentUri(request));
    logger.debug("redirecting to {}", uri);
    redirectStrategy.sendRedirect(request, response, uri);
  }
  
  public static void redirectConfirmSession(HttpServletRequest request, HttpServletResponse response, String loginUri) throws IOException {
    String redirect = String.format("%s/session_callback?redirect=%s", getCurrentUri(request), getFullUrl(request));
    String uri = String.format("%s/confirm_session?redirect=%s", loginUri, redirect);
    logger.debug("redirecting to {}", uri);
    redirectStrategy.sendRedirect(request, response, uri);
  }
  
  private static String getCurrentUri(HttpServletRequest request) {
 // TODO should check for X-Forwared headers, in case of working behind proxy.
    String scheme = request.getScheme();
    String host = request.getServerName();
    Integer port = request.getServerPort();
    String callbackUri = String.format("%s://%s", scheme, host);
    if (port != 80) {
      callbackUri += ":" + port;
    }
    return callbackUri;
  }
  
  private static String getFullUrl(HttpServletRequest request) {
    StringBuffer requestURL = request.getRequestURL();
    String queryString = request.getQueryString();

    if (queryString == null) {
        return requestURL.toString();
    } else {
        return requestURL.append('?').append(queryString).toString();
    }
  }

}
