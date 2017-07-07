package com.nomadays.login;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.nomadays.sso.ConfirmLoginController;
import com.nomadays.sso.ConfirmSessionFilter;
import com.nomadays.sso.SsoServerSettings;

/**
 * 
 * This is just a regular Spring Session configuration, with custom RememberMe behaviour.
 * 
 * Only {@link ConfirmLoginController} is the additional configuration for SSO.
 * 
 * @author beku
 *
 */
@SpringBootApplication
@EnableRedisHttpSession
@RestController
public class SsoLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(SsoLoginApplication.class, args);
	}
	
	@EnableWebSecurity
	@Configuration
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {
		
		private int maxAge = 60 * 60 * 24 * 30; // configuring it to be 30 days

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.addFilterAfter(confirmSessionFilter(), AnonymousAuthenticationFilter.class)
			.authorizeRequests()
				.antMatchers("/free", "/me").permitAll()
				.anyRequest().hasAnyRole("USER")
			.and()
				.formLogin()
			.and()
				.rememberMe()
				.rememberMeServices(new SpringSessionRememberMeServices())
			.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and()
				.csrf()
					.csrfTokenRepository(csrfTokenRepository())
			.and().requestCache().requestCache(requestCache())
			// to support savedRequest for client apps.
			.and().sessionManagement().sessionFixation().migrateSession();
		}
		
		@Bean
		public CookieSerializer cookieSerializer(){
			DefaultCookieSerializer serializer = new DefaultCookieSerializer();
			serializer.setCookieMaxAge(maxAge);
			serializer.setRememberMeRequestAttribute(SpringSessionRememberMeServices.REMEMBER_ME_LOGIN_ATTR);
			return serializer;
		}
		
		@Bean
	    public CsrfTokenRepository csrfTokenRepository(){
	    	CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
	    	csrfTokenRepository.setCookieHttpOnly(false);
	    	return csrfTokenRepository;
	    }
		
		@Bean
		public RequestCache requestCache(){
			return new HttpSessionRequestCache();
		}
		
		@Bean
		public ConfirmSessionFilter confirmSessionFilter() {
		  ConfirmSessionFilter confirmSessionFilter = new ConfirmSessionFilter(ssoServerSettings());
		  confirmSessionFilter.setValiditySeconds(maxAge);
		  return confirmSessionFilter;
		}
		

		
	  @Bean
	  public SsoServerSettings ssoServerSettings(){
	    return new SsoServerSettings();
	  }
		
	}

	@Bean
  public ConfirmLoginController confirmLoginController() {
    return new ConfirmLoginController();
  }
	

	
	@RequestMapping
	public String hello(){
		return "hello";
	}
	
	@RequestMapping("/free")
	public ModelAndView free(){
		return new ModelAndView("free");
	}
	
  @RequestMapping("/me")
  public Object me() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication.getPrincipal();
  }
}
