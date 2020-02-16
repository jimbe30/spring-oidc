package jmb.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	/**
	 * Configuration des infos de référencement de l'application auprès des différents fournisseurs d'identité.
	 * 
	 * @return
	 */
	public ClientRegistrationRepository clientRegistrationRepository() {
		
		String redirectUri = "{baseUrl}/oidcAuth";
		
		ClientRegistration googleRegistration = CommonOAuth2Provider.GOOGLE.getBuilder("google")
				.clientId("656590843516-d87roc2opg8u7lpm2mqu71javnhmcqj6.apps.googleusercontent.com")
				.clientSecret("W3Nw2SgqEX_kIHtGavbKpuYw")
				.redirectUriTemplate(redirectUri)
				.build();
		
		String keycloakBaseUri = "http://localhost:8080/auth/realms/OIDC-demo/protocol/openid-connect"; 
		ClientRegistration keycloakRegistration = ClientRegistration.withRegistrationId("keycloak")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientId("oidcDemoApp")
				.clientSecret("f24fa57d-a8bc-4993-8a3d-afddbf3c6903")
				.redirectUriTemplate(redirectUri)
				.authorizationUri(keycloakBaseUri + "/auth")
				.tokenUri(keycloakBaseUri + "/token")
				.jwkSetUri(keycloakBaseUri + "/certs")
				.userInfoUri(keycloakBaseUri + "/userinfo")
				.userNameAttributeName("preferred_username")
				.build();
		
		return new InMemoryClientRegistrationRepository(googleRegistration, keycloakRegistration);
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http
			.authorizeRequests()
				.antMatchers("/*", "/resources/**", "/accueil").permitAll()
				.antMatchers("/secure/").hasRole("USER")
				.anyRequest().authenticated()
				.and()
			.oauth2Login()
				.redirectionEndpoint().baseUri("/oidcAuth").and()	// doit matcher avec redirectUriTemplate du ClientRegistration
												// (propriété redirect-uri dans application.properties)			
				.loginPage("/login.html")
				.defaultSuccessUrl("/accueil")
				.and()
			.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
				.logoutSuccessUrl("/login.html")
				.permitAll();
	}
	
	


}
