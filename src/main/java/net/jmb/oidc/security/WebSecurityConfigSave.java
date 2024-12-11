package net.jmb.oidc.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


public class WebSecurityConfigSave {
	
	public static final String AUTHORIZATION_BASE_URI = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/";
	public static final String TARGET_URL_PARAM = "redirect_to";
	public static final String[] PERMIT_ALL_REQUEST_MATCHER = {
		"/login/**", "/logout", "/error_401/**", "/", "/token/validate",
		"/error/**", "/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html", 
		"/configuration/**", "/webjars/**"
	};
	

	
	/**
	 * Classe de configuration pour l'authentification en mode "Authorization: Bearer"<br>
	 * Elle est prioritaire sur tout autre mode d'authentification (@Order) 
	 * et filtre les requêtes portant un entête "Authorization: Bearer"
	 */
//	@Configuration
//	@Order(1)
//	public class JwtBearerHttpConfig extends WebSecurityConfigurerAdapter {
//		
//		@Override
		protected void configure(HttpSecurity http) throws Exception {
            http
                .requestMatcher(
                        request -> request.getHeader("Authorization") != null && request.getHeader("Authorization").startsWith("Bearer "))
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(requests -> requests
                        .antMatchers(PERMIT_ALL_REQUEST_MATCHER).permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(server -> server
                        // ici on injecte implicitement le JwtDecoder défini par ailleurs
                        .jwt().and()
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/error_401")))
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .logoutSuccessUrl("/login?success").permitAll());
		}
//
//	}

		

		


}
