package com.nomadays.client1;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.data.redis.RedisOperationsSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.nomadays.sso.SsoAuthenticationEntryPoint;
import com.nomadays.sso.SsoAuthenticationProcessingFilter;

@SpringBootApplication
@EnableRedisHttpSession
@RestController
public class Client1Application {
	
	public static void main(String[] args) {
		SpringApplication.run(Client1Application.class, args);
	}
	
	@EnableWebSecurity
	@Configuration
	public static class SecurityConfig extends WebSecurityConfigurerAdapter {
		
		@Autowired
		private RedisOperationsSessionRepository sessionRepository;
		
		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Bean
		public SsoAuthenticationEntryPoint ssoAuthenticationEntryPoint(){
			return new SsoAuthenticationEntryPoint();
		}
		
		@Bean
		public SsoAuthenticationProcessingFilter ssoAuthenticationProcessingFilter(){
			SsoAuthenticationProcessingFilter filter = new SsoAuthenticationProcessingFilter(sessionRepository, requestCache());
			filter.setAuthenticationManager(authenticationManager);
			return filter;
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.addFilterAt(ssoAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
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
				// this part is not required for SSO.
				.csrf()
				.csrfTokenRepository(csrfTokenRepository())
			.and().requestCache().requestCache(requestCache());
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
			return new CustomRequestCache();
		}
		
		public static class CustomRequestCache extends HttpSessionRequestCache {

			@Override
			public void setRequestMatcher(RequestMatcher requestMatcher) {
				List<RequestMatcher> matchers = new ArrayList<>();
				
				matchers.add(new AntPathRequestMatcher("/form", "POST"));
				matchers.add(requestMatcher);
				
				super.setRequestMatcher(new OrRequestMatcher(matchers));
			}
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
