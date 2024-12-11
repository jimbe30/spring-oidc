package net.jmb.oidc.security;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.util.ArrayUtils;
import com.nimbusds.jwt.JWTParser;

import net.jmb.oidc.model.IdentityProviderRegistration;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig {

	public static final String AUTHORIZATION_BASE_URI = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI	+ "/";
	public static final String TARGET_URL_PARAM = "redirect_to";
	public static final String[] PERMIT_ALL_REQUEST_MATCHER = { "/login/**", "/logout", "/error_401/**", "/",
			"/token/validate", "/error/**", "/v2/api-docs", "/swagger-resources/**", "/swagger-ui.html",
			"/configuration/**", "/webjars/**" };

	@Value("${server.servlet.context-path:}")
	String contextPath;
	
	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;


	@Bean
	Map<String, IdentityProviderRegistration> idpRegistrations(Environment env) {
		Map<String, IdentityProviderRegistration> result = new HashMap<>();
		((InMemoryClientRegistrationRepository) clientRegistrationRepository).forEach(
			registration -> {
				String registrationId = registration.getRegistrationId();
				String clientId = registration.getClientId();
				String authPath = AUTHORIZATION_BASE_URI + registration.getRegistrationId();
				String description = (String) registration.getClientName();
				String authorizationURL = registration.getProviderDetails().getAuthorizationUri();
				String iconUrl = env.getProperty(registrationId + ".iconUrl");
				IdentityProviderRegistration idpRegistration = new IdentityProviderRegistration()
					.setAuthorizationPath(authPath).setClientId(clientId).setDescription(description)
					.setAuthorizationURL(authorizationURL).setRegistrationId(registrationId)
					.setIconUrl(iconUrl);
				String issuer = env.getProperty(registrationId + ".issuer");
				if (issuer == null) {
					try {
						URI uri = new URI(authorizationURL);
						issuer = uri.getHost();
					} catch (URISyntaxException e) {
						e.printStackTrace();
					}
				}
				idpRegistration.setIssuer(issuer);
				result.put(registrationId, idpRegistration);
			}
		);
		return result;
	}
	

	/**
	 * Configuration pour l'authentification selon protocole OIDC <br>
	 * Exécutée pour les requêtes ne portant pas d'entête "Authorization: Bearer" <br>
	 * Redirige les utilisateurs non authentifiés vers une page de login contenant
	 * les liens vers les IDP enregistrés
	 */
	@Bean
	SecurityFilterChain oidcClientFilterChain(HttpSecurity http) throws Exception {
		String[] permitAllRequestMatcher = ArrayUtils.concat(PERMIT_ALL_REQUEST_MATCHER, new String[] { "/accueil" });
        http
        	.cors(Customizer.withDefaults())
			.authorizeRequests(
				requests -> requests
					.antMatchers(permitAllRequestMatcher).permitAll()
					.anyRequest().authenticated())
			.sessionManagement(
					management -> management.sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy()))
			.oauth2Login(
				loginConf -> loginConf
					.loginPage("/login")
					.authorizationEndpoint(
						endpointConf -> endpointConf.authorizationRequestResolver(new AuthorizationRequestResolver(clientRegistrationRepository))
					)
					.tokenEndpoint(
						endpointConf -> endpointConf.accessTokenResponseClient(accessTokenResponseClient())							
					)
					.userInfoEndpoint(
						endpointConf -> endpointConf.oidcUserService(oidcUserService())
					)
//					.successHandler(this.successHandler())
					.defaultSuccessUrl("/token/ok")
			)
			.logout(
				logoutConf -> logoutConf
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.logoutSuccessUrl("/login")
					.permitAll()
			);
		return http.build();
	}
	
	@Bean
	JwtDecoderFactory<ClientRegistration> jwtTokenDecoderFactory() {
		return clientRegistration -> {			
			NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
				.withJwkSetUri(clientRegistration.getProviderDetails().getJwkSetUri())
				.restOperations(new RestTemplate(requestFactory(clientRegistration)))
				.build();
			jwtDecoder.setJwtValidator(
				new DelegatingOAuth2TokenValidator<>(
					new JwtTimestampValidator(),
					new OidcIdTokenValidator(clientRegistration)
				)
			);
			jwtDecoder.setClaimSetConverter(
				new ClaimTypeConverter(
					OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()
				)
			);
			return jwtDecoder;		
		};
	}
	
	
	private ClientHttpRequestFactory requestFactory(ClientRegistration clientRegistration) {
		SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
		if (clientRegistration.getRegistrationId().equals("google")) {
			Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress("isp-ceg.emea.cegedim.grp", 3128));
			requestFactory.setProxy(proxy);
		}
		return requestFactory;
	}
	
	
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {		
		return (authorizationGrantRequest) -> {
			OAuth2AccessTokenResponse result = null;
			DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();
			RestTemplate restTemplate = new RestTemplate(
					Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
			restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
			restTemplate.setRequestFactory(requestFactory(authorizationGrantRequest.getClientRegistration()));
			delegate.setRestOperations(restTemplate);
			result = delegate.getTokenResponse(authorizationGrantRequest);
			return result;			
		};
	}
	
	
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		return (userRequest) -> {
			// Delegate to the default implementation for loading a user			
			OidcUserService oidcUserService = new OidcUserService();
			DefaultOAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
			oidcUserService.setOauth2UserService(oAuth2UserService);
			ClientHttpRequestFactory requestFactory = requestFactory(userRequest.getClientRegistration());
			oAuth2UserService.setRestOperations(new RestTemplate(requestFactory));
			OidcUser oidcUser = oidcUserService.loadUser(userRequest);
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
			mappedAuthorities.addAll(oidcUser.getAuthorities());
			if ("admin".equalsIgnoreCase(oidcUser.getAttribute("profile"))) {
				mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
			}
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
			return oidcUser;
		};
	}


	/**
	 * Retourne le JwtDecoder utilisé pour valider un jeton JWT et extraire ses données  en tenant
	 * compte de l'ensemble des fournisseurs d'identité enregistrés pour l'application
	 * @param clientRegistrationRepository
	 * @return JwtDecoder
	 */
	@Bean
	JwtDecoder jwtDecoder(InMemoryClientRegistrationRepository clientRegistrationRepository, JwtDecoderFactory<ClientRegistration> jwtTokenDecoderFactory) {
		Function<String, ClientRegistration> clientRegistrationSelector = issuer -> {
			for (ClientRegistration registration : clientRegistrationRepository) {
				String registrationIssuerUri = registration.getProviderDetails().getIssuerUri();
				if (!StringUtils.hasText(registrationIssuerUri)) {
					registrationIssuerUri = registration.getProviderDetails().getAuthorizationUri();
				}
				if (!StringUtils.hasText(registrationIssuerUri)) {
					registrationIssuerUri = registration.getProviderDetails().getTokenUri();
				}
				if (!StringUtils.hasText(registrationIssuerUri)) {
					registrationIssuerUri = registration.getProviderDetails().getUserInfoEndpoint().getUri();
				}
				if (StringUtils.hasText(registrationIssuerUri) && (registrationIssuerUri.contains(issuer) || issuer.contains(registrationIssuerUri))) {
					return registration;
				}
			}
			return null;
		};
		return token -> {
			try {
				JwtDecoder decoder = null;
				String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
				ClientRegistration clientRegistration = clientRegistrationSelector.apply(issuer);
				if (clientRegistration != null) {
					decoder = jwtTokenDecoderFactory().createDecoder(clientRegistration);
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

	/**
	 * Utilise <code>DefaultOAuth2AuthorizationRequestResolver</code> pour
	 * construire la requête d'autorisation auprès de l'IDP et sauvegarde dans la
	 * session les paramètres de la requête initiale.<br>
	 * Ces paramètres pourront utilement être récupérés par un
	 * <code>AuthenticationSuccessHandler</code> en particulier pour rediriger la
	 * réponse vers l'URL souhaitée
	 */
	public class AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

		public static final String SAVED_PARAMETERS_ATTR_NAME = "AuthorizationRequestResolverWithParameters.SAVED_PARAMETERS";
		private DefaultOAuth2AuthorizationRequestResolver delegate;

		AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
			this.delegate = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, AUTHORIZATION_BASE_URI);
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

		public OAuth2AuthorizationRequest saveParameters(HttpServletRequest request,
				OAuth2AuthorizationRequest authorizationRequest) {
			if (authorizationRequest != null) {
				HttpSession session = request.getSession();
				HashMap<String, String[]> params = new HashMap<>();
				params.putAll(request.getParameterMap());
				session.setAttribute(SAVED_PARAMETERS_ATTR_NAME, params);
			}
			return authorizationRequest;
		}
	}
	
	
//	/**
//	 * En cas d'authentification réussie, récupère les paramètres de la requête initiale 
//	 * sauvegardés dans la session (y compris l'URL cible via <code>targetUrlParameter</code>) 
//	 * et rediriqe la réponse vers l'URL cible avec ces paramètres sous forme de queryString
//	 * @param targetUrlParameter
//	 * @param defaultTargetUrl
//	 * @return
//	 */
//	private AuthenticationSuccessHandler successHandler(String targetUrlParameter, String defaultTargetUrl) {
//		
//		class CustomOidcAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {				
//			@Override
//			protected String determineTargetUrl(HttpServletRequest request,	HttpServletResponse response, Authentication authentication) {
//				
//				HttpSession session = request.getSession();
//				String targetUrl = super.determineTargetUrl(request, response);
//				String targetUrlParameter = getTargetUrlParameter();
//				StringBuffer queryParams = new StringBuffer();
//		
//				@SuppressWarnings("unchecked")
//				Map<String, String[]> parameters = (Map<String, String[]>) session.getAttribute(
//						AuthorizationRequestResolverWithParameters.SAVED_PARAMETERS_ATTR_NAME);
//								
//				if (parameters != null) {
//					final StringBuffer tmpTargetUrl = new StringBuffer();
//					parameters.forEach((paramKey, paramValues) -> {
//						if (targetUrlParameter != null && paramKey.equals(targetUrlParameter)) {
//							if (StringUtils.hasText(paramValues[0])) {
//								tmpTargetUrl.append(paramValues[0].trim());
//							}
//						} else {
//							Arrays.stream(paramValues).forEach(paramValue -> {
//								queryParams
//									.append(queryParams.length() > 0 ? "&" : "?")
//									.append(paramKey + "=" + paramValue);									
//							});
//
//						}
//					});
//					if (tmpTargetUrl.length() > 0) {
//						targetUrl = tmpTargetUrl.toString();
//					}
//				}
//				
//				if (authentication.getPrincipal() instanceof OidcUser) {
//					OidcUser user = (OidcUser) authentication.getPrincipal();
//					String jwt = user.getIdToken().getTokenValue();	
//					response.addHeader("Authorization", "Bearer " + jwt);
//					queryParams
//						.append(queryParams.length() > 0 ? "&" : "?")
//						.append("token_type=Bearer")
//						.append("&id_token=" + jwt);
//				}
//				targetUrl = targetUrl.concat(queryParams.toString());
//				session.invalidate();
//				return targetUrl;
//			}
//		}
//		
//		CustomOidcAuthenticationSuccessHandler successHandler = new CustomOidcAuthenticationSuccessHandler();
//		successHandler.setDefaultTargetUrl(defaultTargetUrl);
//		successHandler.setTargetUrlParameter(targetUrlParameter);
//		return successHandler;			
//	}


}
