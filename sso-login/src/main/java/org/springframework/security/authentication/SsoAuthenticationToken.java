package org.springframework.security.authentication;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public class SsoAuthenticationToken extends AbstractAuthenticationToken {

	public SsoAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		// TODO Auto-generated constructor stub
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return null;
	}

}
