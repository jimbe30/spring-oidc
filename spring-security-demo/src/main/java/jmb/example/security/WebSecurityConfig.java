package jmb.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig 
extends WebSecurityConfigurerAdapter 
{
	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http
//			.authorizeRequests()
//				.antMatchers("/", "/accueil").permitAll()
//				.anyRequest().authenticated()
//				.and()
//			.oauth2Login()
//				.and()
//			.logout()
//				.permitAll();
//	}
	
	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		ClientRegistration googleRegistration = clientRegistrationRepository.findByRegistrationId("google");
		System.out.println("google.redirectUriTemplate: " + googleRegistration.getRedirectUriTemplate());
		
		http
			.authorizeRequests()
				.antMatchers("/", "/accueil").permitAll()
				.anyRequest().authenticated()
				.and()
			.oauth2Login()
				.redirectionEndpoint().baseUri("/oidcAuth").and()	// doit matcher avec redirectUriTemplate du ClientRegistration
				// (propriete redirect-uri dans application.properties)			
				.and()
			.logout()
				.permitAll();
	}
	
	


}
