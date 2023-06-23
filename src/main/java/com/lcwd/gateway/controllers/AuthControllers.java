package com.lcwd.gateway.controllers;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lcwd.gateway.models.AuthResponse;

@RestController
@RequestMapping("/auth")
public class AuthControllers {

	private Logger logger = LoggerFactory.getLogger(AuthControllers.class);
	
	@GetMapping("/login")
	public ResponseEntity<AuthResponse> login(
			@RegisteredOAuth2AuthorizedClient("okta") OAuth2AuthorizedClient client,
			@AuthenticationPrincipal OidcUser oidcUser,
			Model model
			){		// Here we will get some Objects
		
		logger.info("user email id {}:",oidcUser.getEmail());
		AuthResponse response = new AuthResponse();
		
		// Setting user id to response. 
		response.setUserId(oidcUser.getEmail());
		
		// Setting token to auth response
		response.setAccessToken(client.getAccessToken().getTokenValue());
		
		response.setRefreshToken(client.getRefreshToken().getTokenValue());
		
		response.setExpireAt(client.getAccessToken().getExpiresAt().getEpochSecond());
		
		List<String> authorities = oidcUser.getAuthorities().stream().map(grantedAuthority -> {
			return grantedAuthority.getAuthority();
		}).collect(Collectors.toList());
		
		response.setAuthories(authorities);
		
		return new ResponseEntity<>(response,HttpStatus.OK);
		
	}
	
}
