package com.nomadays.login;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
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
			redirectStrategy.sendRedirect(request, response, redirect + "?token=" + encryptAndEncode(session.getId()));
		}
		else {
			throw new AccessDeniedException("Illegal redirect uri");
		}
		
	}
	
	
	private String encryptAndEncode(String token){
		try {
			 String key = "G~Y@86-FtH&gq'_e"; // 128 bit key, better be handled in external properties
	         // Create key and cipher
	         Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
	         Cipher cipher = Cipher.getInstance("AES");
	         // encrypt the text
	         cipher.init(Cipher.ENCRYPT_MODE, aesKey);
	         byte[] encrypted = cipher.doFinal(token.getBytes());
	         // encode
	         String encoded = new String( Base64.getUrlEncoder().encode(encrypted));
	         return encoded;
		
		} catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException e) {
			
		} 
		return null;
	}
}
