package com.nomadays.client1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.data.redis.RedisOperationsSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.nomadays.sso.SsoAuthenticationEntryPoint;
import com.nomadays.sso.SsoClientLoginCallbackFilter;
import com.nomadays.sso.SsoClientLoginFilter;
import com.nomadays.sso.SsoClientSessionCheckFilter;

@SpringBootApplication
@EnableRedisHttpSession
@RestController
public class Client1Application {
  
  /**
   * To differ from default SPRING_SECURITY_SAVED_REQUEST,
   * this way it can save have different SavedRequest from main login app.
   * 
   * should NOT start with 'SPRING_SECURITY_', then it wont be migrated
   */
  private static final String SAVED_REQUEST = "Client1Application_SAVED_REQUEST";
	
	public static void main(String[] args) {
		SpringApplication.run(Client1Application.class, args);
	}
	
	@EnableWebSecurity
	@Configuration
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {
		
		@Autowired
		private RedisOperationsSessionRepository sessionRepository;
		
		@Bean
		public SsoAuthenticationEntryPoint ssoAuthenticationEntryPoint(){
			return new SsoAuthenticationEntryPoint();
		}
		
		@Bean
		public SsoClientLoginFilter ssoClientLoginFilter(){
			return new SsoClientLoginFilter(ssoAuthenticationEntryPoint());
		}
		
		@Bean
		public SsoClientLoginCallbackFilter ssoClientLoginCallbackFilter(){
		  SsoClientLoginCallbackFilter ssoClientLoginCallbackFilter =
		      new SsoClientLoginCallbackFilter(sessionRepository);
		  ssoClientLoginCallbackFilter.setSavedRequestAttr(SAVED_REQUEST);
			return ssoClientLoginCallbackFilter;
		}
		
		@Bean
		public SsoClientSessionCheckFilter ssoClientSessionCheckFilter() {
		  return new SsoClientSessionCheckFilter();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.addFilterBefore(ssoClientLoginCallbackFilter(), WebAsyncManagerIntegrationFilter.class)
			.addFilterAfter(ssoClientSessionCheckFilter(), SsoClientLoginCallbackFilter.class)
			.addFilterAfter(ssoClientLoginFilter(), SsoClientSessionCheckFilter.class)
			
			.authorizeRequests()
				.antMatchers("/free").permitAll()
				.anyRequest().hasAnyRole("USER")
			.and()
				.exceptionHandling()
					.authenticationEntryPoint(ssoAuthenticationEntryPoint())
			.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	    .and()
	      .requestCache().requestCache(requestCache())
			.and()
				// this part is not required for SSO.
				.csrf()
				.csrfTokenRepository(csrfTokenRepository());
		}
		
		/**
		 * We need CookieCsrfTokenRepository, so it doesn't expire at all.
		 * You could probably need csrf configuration, this part is not required for SSO.
		 * @return
		 */
		@Bean
	    public CsrfTokenRepository csrfTokenRepository(){
	    	CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
	    	csrfTokenRepository.setCookieHttpOnly(false);
	    	return csrfTokenRepository;
	    }
		
		@Bean
		public RequestCache requestCache(){
		  HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		  requestCache.setSessionAttrName(SAVED_REQUEST);
			return requestCache;
		}
		
	}
	
	@RequestMapping
	public String hello(){
		return "hello";
	}
	
	@RequestMapping("/free")
	public ModelAndView free(){
		return new ModelAndView("free");
	}
}
