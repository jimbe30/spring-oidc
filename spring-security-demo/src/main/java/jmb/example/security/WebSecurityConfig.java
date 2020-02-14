package jmb.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("google");
		System.out.println("google");
		System.out.println("- redirectUriTemplate: " + registration.getRedirectUriTemplate());
		System.out.println("- token-uri: " + registration.getProviderDetails().getTokenUri());
		
		registration = clientRegistrationRepository.findByRegistrationId("github");
		System.out.println("github");
		System.out.println("- redirectUriTemplate: " + registration.getRedirectUriTemplate());
		System.out.println("- token-uri: " + registration.getProviderDetails().getTokenUri());
		
		registration = clientRegistrationRepository.findByRegistrationId("keycloak");
		System.out.println("keycloak");
		System.out.println("- redirectUriTemplate: " + registration.getRedirectUriTemplate());
		System.out.println("- token-uri: " + registration.getProviderDetails().getTokenUri());
		
		
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
