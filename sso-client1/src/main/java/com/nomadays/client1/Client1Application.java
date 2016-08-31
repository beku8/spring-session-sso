package com.nomadays.client1;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisOperationsSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nomadays.sso.SsoAuthenticationEntryPoint;
import com.nomadays.sso.SsoAuthenticationProcessingFilter;
import com.nomadays.sso.SsoFilter;

@SpringBootApplication
@EnableRedisHttpSession
@RestController
public class Client1Application {
	
	public static void main(String[] args) {
		SpringApplication.run(Client1Application.class, args);
	}
	
	@Bean
	public FilterRegistrationBean ssoFilterBean(RedisOperationsSessionRepository sessionRepository) {
		FilterRegistrationBean filter = new FilterRegistrationBean(ssoFilter(sessionRepository));
		filter.setOrder(0);
		return filter;
	}
	
//	 @Bean
//	    public FilterRegistrationBean securityFilterBean(@Qualifier(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME) Filter securityFilter){
//	    	FilterRegistrationBean filter = new FilterRegistrationBean(securityFilter);
//	    	filter.setOrder(2);
//	    	filter.setName(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME);
//	    	return filter; 
//	    }
	
	@Bean
	public SsoFilter ssoFilter(RedisOperationsSessionRepository sessionRepository){
		return new SsoFilter(sessionRepository);
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
			SsoAuthenticationProcessingFilter filter = new SsoAuthenticationProcessingFilter(sessionRepository);
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
				.anyRequest().hasAnyRole("USER")
			.and()
//				.formLogin()
				.exceptionHandling()
					.authenticationEntryPoint(ssoAuthenticationEntryPoint())
			.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
		}
		
	}
	
	@RequestMapping
	public String hello(){
		return "hello";
	}
}
