package com.nomadays.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nomadays.sso.SpringSessionRememberMeServices;
import com.nomadays.sso.SsoServerSettings;

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
		
		private int maxAge = 60 * 60 * 24 * 30;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.authorizeRequests()
				.anyRequest().hasAnyRole("USER")
			.and()
				.formLogin()
			.and()
				.rememberMe()
				.rememberMeServices(rememberMeServices())
			.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and()
				.csrf()
					.csrfTokenRepository(csrfTokenRepository());
		}
		
		
		public RememberMeServices rememberMeServices(){
			return new SpringSessionRememberMeServices(maxAge);
		}
		
		@Bean
		public CookieSerializer cookieSerializer(){
			DefaultCookieSerializer serializer = new DefaultCookieSerializer();
			serializer.setCookieMaxAge(maxAge);
			return serializer;
		}
		
		@Bean
	    public CsrfTokenRepository csrfTokenRepository(){
	    	CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
	    	csrfTokenRepository.setCookieHttpOnly(false);
	    	return csrfTokenRepository;
	    }
		
	}
	
	@Bean
	public SsoServerSettings ssoServerSettings(){
		return new SsoServerSettings();
	}
	
	@RequestMapping
	public String hello(){
		return "hello";
	}
}
