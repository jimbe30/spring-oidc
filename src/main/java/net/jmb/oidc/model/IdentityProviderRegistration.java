package net.jmb.oidc.model;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class IdentityProviderRegistration {
	
	String registrationId;
	String clientId;
	String description;
	String authorizationPath;
	String authorizationURL;
	String iconUrl;
	String issuer;
	@JsonIgnore
	JwtDecoder jwtDecoder; 
	
	public String getRegistrationId() {
		return registrationId;
	}
	public IdentityProviderRegistration setRegistrationId(String registrationId) {
		this.registrationId = registrationId;
		return this;
	}
	public String getClientId() {
		return clientId;
	}
	public IdentityProviderRegistration setClientId(String clientId) {
		this.clientId = clientId;
		return this;
	}
	public String getDescription() {
		return description;
	}
	public IdentityProviderRegistration setDescription(String idpDescription) {
		this.description = idpDescription;
		return this;
	}
	public String getAuthorizationPath() {
		return authorizationPath;
	}
	public IdentityProviderRegistration setAuthorizationPath(String authorizationURL) {
		this.authorizationPath = authorizationURL;
		return this;
	}
	public String getIssuer() {
		return issuer;
	}
	public IdentityProviderRegistration setIssuer(String issuer) {
		this.issuer = issuer;
		return this;
	}
	public String getAuthorizationURL() {
		return authorizationURL;
	}
	public IdentityProviderRegistration setAuthorizationURL(String authorizationURL) {
		this.authorizationURL = authorizationURL;
		return this;
	}
	public JwtDecoder getJwtDecoder() {
		return jwtDecoder;
	}
	public IdentityProviderRegistration setJwtDecoder(JwtDecoder jwtDecoder) {
		this.jwtDecoder = jwtDecoder;
		return this;		
	}
	public String getIconUrl() {
		return iconUrl;
	}
	public IdentityProviderRegistration setIconUrl(String iconUrl) {
		this.iconUrl = iconUrl;
		return this;		
	}	
	
	

	
}
