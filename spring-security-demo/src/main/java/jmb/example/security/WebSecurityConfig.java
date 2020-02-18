package jmb.example.security;

import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.nimbusds.jwt.JWTParser;

@EnableWebSecurity
public class WebSecurityConfig {	

	/**
	 * Configuration des infos de référencement de l'application auprès des différents fournisseurs d'identité.
	 * @return
	 */
	@Bean
	public static ClientRegistrationRepository clientRegistrationRepository() {
		
		String redirectUri = "{baseUrl}/oidcAuth";
		
		ClientRegistration googleRegistration = CommonOAuth2Provider.GOOGLE.getBuilder("google")
				.clientId("656590843516-d87roc2opg8u7lpm2mqu71javnhmcqj6.apps.googleusercontent.com")
				.clientSecret("W3Nw2SgqEX_kIHtGavbKpuYw")
				.redirectUriTemplate(redirectUri)
				.build();
		
		String keycloakBaseUri = "http://localhost:8180/auth/realms/OIDC-demo/protocol/openid-connect"; 
		ClientRegistration keycloakRegistration = ClientRegistration.withRegistrationId("keycloak")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("profile", "email", "openid")
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
	
	/**
	 * Le JwtDecoder utilisé pour l'authentification par header en mode "Authorization: Bearer" (http.oauth2ResourceServer().jwt())
	 * tient compte de l'ensemble des fournisseurs d'identité enregistrés pour l'application (ClientRegistrationRepository) 
	 * @param clientRegistrationRepository
	 * @return JwtDecoder
	 */
	@Bean
	public static JwtDecoder jwtDecoder(InMemoryClientRegistrationRepository clientRegistrationRepository) {
		
		return token -> {
			try {
				JwtDecoder decoder = null;
				String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
				for (ClientRegistration registration: clientRegistrationRepository) {
					if (registration.getProviderDetails().getAuthorizationUri().contains(issuer)) {
						decoder = NimbusJwtDecoder
								.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
								.build();
						break;
					}
				}				
				if (decoder == null) {
					throw new JwtException("Accès interdit: aucune clé connue pour valider le jeton fourni");					
				}				
				return decoder.decode(token);				
			} catch (ParseException pe) {
				throw new JwtException(pe.getMessage());
			}
		};
	}
	
	@Configuration @Order(1)
	public static class JwtBearerHttpConfig extends WebSecurityConfigurerAdapter {		
		@Override
		protected void configure(HttpSecurity http) throws Exception {			
			http
				.requestMatcher(
					request -> request.getHeader("Authorization") != null && request.getHeader("Authorization").startsWith("Bearer ")
				)
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.oauth2ResourceServer()
					.jwt()	// ici on récupère implicitement le JwtDecoder défini plus haut
						.and()
					.and()
				.authorizeRequests()
					.antMatchers("/*", "/accueil").permitAll()
					.anyRequest().authenticated()
					.and()
				.logout()				
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.logoutSuccessUrl("/login.html")
					.permitAll();
		}		
	}
	
	@Configuration @Order(5)
	public static class OidcHttpConfig extends WebSecurityConfigurerAdapter {		
		@Override
		protected void configure(HttpSecurity http) throws Exception {			
			http
				.authorizeRequests()
					.antMatchers("/*", "/accueil").permitAll()
					.antMatchers("/secure/ressources/nouvelle").hasRole("USER")
					.antMatchers("/secure/**").hasRole("ADMIN")
					.anyRequest().authenticated()
					.and()
				.oauth2Login()
					.redirectionEndpoint().baseUri("/oidcAuth").and()	// doit matcher avec redirectUriTemplate du ClientRegistration
													// (propriété redirect-uri dans application.properties)			
					.loginPage("/login.html")
					.defaultSuccessUrl("/accueil")
					.userInfoEndpoint()
						.oidcUserService(oidcUserService())
						.userService(userService())
						.and()
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.logoutSuccessUrl("/login.html")
					.permitAll();
		}
		
		private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
			final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();		

	        return (userRequest) -> {
	            // Delegate to the default implementation for loading a user
	        	OAuth2User user = delegate.loadUser(userRequest);

	            OAuth2AccessToken accessToken = userRequest.getAccessToken();
	            Map<String, Object> attributes = new HashMap<>();
	            attributes.putAll(user.getAttributes());
	            attributes.computeIfAbsent("idToken", k -> accessToken.getTokenValue());      
	            
	            user = new DefaultOAuth2User(user.getAuthorities(), attributes, 
	            		userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
	            return user;
	        };
		}

		private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
	        final OidcUserService delegate = new OidcUserService();

	        return (userRequest) -> {
	            // Delegate to the default implementation for loading a user
	            OidcUser oidcUser = delegate.loadUser(userRequest);

	            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
	            mappedAuthorities.addAll(oidcUser.getAuthorities());
	            
	            if ("admin".equals(oidcUser.getAttribute("profile"))) {
	            	mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
	            }	            
	            System.out.println(oidcUser.getIdToken().getTokenValue());

	            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
	            return oidcUser;
	        };
	    }		
	}	
	
}
