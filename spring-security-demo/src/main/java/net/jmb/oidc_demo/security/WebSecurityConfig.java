package net.jmb.oidc_demo.security;

import java.text.ParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.nimbusds.jwt.JWTParser;

import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@EnableWebSecurity
public class WebSecurityConfig {
	
	public static final String AUTHORIZATION_BASE_URI = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/";

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;
	
	@Bean
	public Map<String, IdentityProviderRegistration> idpRegistrations () {
		
		Map<String, IdentityProviderRegistration> result = new HashMap<>();
		
		((InMemoryClientRegistrationRepository) clientRegistrationRepository).forEach(
				
			registration -> {
				
				String registrationId = registration.getRegistrationId();
				String clientId = registration.getClientId();
				String authPath = AUTHORIZATION_BASE_URI + registration.getRegistrationId();
				String description = (String) registration.getClientName();
				String issuerURL = registration.getProviderDetails().getAuthorizationUri();
			
				IdentityProviderRegistration idpRegistration = 	
					new IdentityProviderRegistration()
						.setAuthorizationPath(authPath)
						.setClientId(clientId)
						.setDescription(description)
						.setIssuerURL(issuerURL)
						.setRegistrationId(registrationId);
				
				result.put(registrationId, idpRegistration);
			}
		);
		
		return result;
	}
	
	/**
	 * Classe de configuration pour l'authentification en mode "Authorization: Bearer"<br>
	 * Elle est prioritaire sur tout autre mode d'authentification (@Order) 
	 * et filtre les requêtes portant un entête "Authorization: Bearer"
	 * @return JwtDecoder
	 */
	@Configuration
	@Order(1)
	public class JwtBearerHttpConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.requestMatcher(
						request -> request.getHeader("Authorization") != null && request.getHeader("Authorization").startsWith("Bearer "))
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.oauth2ResourceServer()
					// ici on injecte implicitement le JwtDecoder défini ci-dessous
					.jwt().and()
					.and()
				.authorizeRequests()
					.antMatchers("/login/*", "/", "/accueil").permitAll()
					.anyRequest().authenticated()
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.logoutSuccessUrl("/login.html").permitAll();
		}
		
		/**
		 * Retourne le JwtDecoder utilisé pour l'authentification en mode "Authorization: Bearer" 
		 * et qui tient compte de l'ensemble des fournisseurs d'identité enregistrés pour
		 * l'application (ClientRegistrationRepository)
		 * @param clientRegistrationRepository
		 * @return JwtDecoder
		 */
		@Bean
		public JwtDecoder jwtDecoder(InMemoryClientRegistrationRepository clientRegistrationRepository) {

			return token -> {
				try {
					JwtDecoder decoder = null;
					String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
					for (ClientRegistration registration : clientRegistrationRepository) {
						if (registration.getProviderDetails().getAuthorizationUri().contains(issuer)) {
							decoder = NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
									.build();
							break;
						}
					}
					if (decoder == null) {
						throw new JwtException("Accès interdit: aucun fournisseur IDP connu pour valider le jeton fourni");
					}
					return decoder.decode(token);
				} catch (ParseException pe) {
					throw new JwtException(pe.getMessage());
				}
			};
		}
	}

	/**
	 * Classe de configuration pour l'authentification en mode OIDC
	 * Elle est exécutée pour les requêtes ne portant pas d'entête "Authorization: Bearer" 
	 * et redirige l'utilisateur vers la page de login contenant les liens vers les fournisseurs 
	 * d'identité enregistrés (dans le ClientRegistrationRepository)
	 */
	@Configuration
	@Order(5)
	public class OidcHttpConfig extends WebSecurityConfigurerAdapter {
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/", "accueil", "/login/*").permitAll()
					.anyRequest().authenticated()
					.and()
				.sessionManagement()
					.sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
					.and()
				.oauth2Login()
					.authorizationEndpoint()
						.authorizationRequestResolver(
							new AuthorizationRequestResolverWithParameters(clientRegistrationRepository))
						.and()
					.loginPage("/error_401")
					.successHandler(this.successHandler("redirect_to", "/accueil"))
					.userInfoEndpoint()
						.oidcUserService(this.oidcUserService())
						.and()
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.logoutSuccessUrl("/login").permitAll();
		}
		/**
		 * Utilise <code>DefaultOAuth2AuthorizationRequestResolver</code> pour construire la requête
		 * d'authorisation auprès de l'IDP et sauvegarde dans la session les paramètres de la requête initiale.<br>
		 * Ces paramètres pourront utilement être récupérés par un <code>AuthenticationSuccessHandler</code>
		 * en particulier pour rediriger la réponse vers l'URL souhaitée
		 */
		public class AuthorizationRequestResolverWithParameters implements OAuth2AuthorizationRequestResolver {

			public static final String SAVED_PARAMETERS_ATTR_NAME = "AuthorizationRequestResolverWithParameters.SAVED_PARAMETERS";
			private DefaultOAuth2AuthorizationRequestResolver delegate;

			AuthorizationRequestResolverWithParameters(
					ClientRegistrationRepository clientRegistrationRepository) {
				this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
						clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
			}
			@Override
			public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
				OAuth2AuthorizationRequest authorizationRequest = this.delegate.resolve(request);
				return this.saveParameters(request, authorizationRequest);
			}
			@Override
			public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
				OAuth2AuthorizationRequest authorizationRequest = this.delegate.resolve(request, clientRegistrationId);
				return this.saveParameters(request, authorizationRequest);
			}
			public OAuth2AuthorizationRequest saveParameters(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
				if (authorizationRequest != null) {
					HttpSession session = request.getSession();					
					HashMap<String, String[]> params = new HashMap<>();
					params.putAll(request.getParameterMap());
					session.setAttribute(SAVED_PARAMETERS_ATTR_NAME, params);
				}
				return authorizationRequest;
			}
		}
		
		private AuthenticationSuccessHandler successHandler(String targetUrlParameter, String defaultTargetUrl) {
			
			class CustomOidcAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {				
				@Override
				protected String determineTargetUrl(HttpServletRequest request,	HttpServletResponse response, Authentication authentication) {
					String targetUrl = super.determineTargetUrl(request, response);
					String targetUrlParameter = getTargetUrlParameter();	
					HttpSession session = request.getSession();
					if (targetUrlParameter != null) {						
						@SuppressWarnings("unchecked")
						Map<String, String[]> parameters = (Map<String, String[]>) session.getAttribute(
								AuthorizationRequestResolverWithParameters.SAVED_PARAMETERS_ATTR_NAME);
						if (parameters != null && parameters.get(targetUrlParameter) != null) {
							if (StringUtils.hasText(parameters.get(targetUrlParameter)[0])) {
								targetUrl = parameters.get(targetUrlParameter)[0];
							}
						}
					}
					if (authentication.getPrincipal() instanceof OidcUser) {
						OidcUser user = (OidcUser) authentication.getPrincipal();
						String jwt = user.getIdToken().getTokenValue();	
						response.addHeader("Authorization", "Bearer " + jwt);
						targetUrl += "?access_token=" + jwt;
					}
					session.invalidate();
					return targetUrl;
				}
			}
			
			CustomOidcAuthenticationSuccessHandler successHandler = new CustomOidcAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl(defaultTargetUrl);
			successHandler.setTargetUrlParameter(targetUrlParameter);
			return successHandler;			
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
