package net.jmb.oidc_demo.controllers;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import net.jmb.oidc_demo.security.WebSecurityConfig;

@Controller
public class AuthController {

	InMemoryClientRegistrationRepository clientRegistrationRepository;
	Map<String, Map<String, String>> loginInfos;
	
	@Autowired
	AuthController(
		ClientRegistrationRepository clientRegistrationRepository,
		@Value("${net.jmb.oidc-app.base-path}")	String basePath) {
		
			this.clientRegistrationRepository = (InMemoryClientRegistrationRepository) clientRegistrationRepository;
			loginInfos = new ConcurrentHashMap<>();
			
			this.clientRegistrationRepository.forEach(
				registration -> {
					String idProvider = registration.getRegistrationId();
					String authURL = basePath + WebSecurityConfig.AUTHORIZATION_BASE_URI + registration.getRegistrationId();
					String authDescription = (String) registration.getProviderDetails().getConfigurationMetadata().get(WebSecurityConfig.IDP_INFO_KEY);
					Map<String, String> authInfos = new HashMap<>();
					authInfos.put("URL", authURL);
					authInfos.put("description", authDescription);
					loginInfos.put(idProvider, authInfos);				
				}
			);
	}
	
	@GetMapping("/login/infos")
	@ResponseBody
	public Map<String, Map<String, String>> loginInfos() {
		return loginInfos;
	}

	@RequestMapping("/login")
	public ModelAndView login(HttpServletRequest request,
			@RequestParam(value = "redirect_to", required = false) String redirectTo) {

		if (StringUtils.isEmpty(redirectTo)) {
			redirectTo = request.getHeader("Referer");
		}
		Map<String, String> body = null;
		if (StringUtils.hasText(redirectTo)) {
			body = new HashMap<String, String>();
			body.put("redirect_to", "redirect_to=" + redirectTo);
		}
		return new ModelAndView("loginPage", body);
	}
	
	@RequestMapping("/error_401")
	public ResponseEntity<Object> erreur401() {				
		return erreur401(null);
	}

	@RequestMapping("/error_401/{appName}")
	public ResponseEntity<Object> erreur401(@PathVariable(required = false) String appName) {
		
		String redirectParameter = "redirect_to";
		
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.set("login-urls",
			loginInfos.values().stream()
				.map(
					map -> {
						return map.get("URL");
					}
				)
				.collect(Collectors.toList())
				.toString()
		);

		responseHeaders.set("redirect-parameter", redirectParameter);
		if (appName != null) {
			responseHeaders.set("www-authenticate", "Bearer realm=\"" + appName + "\"");
		}
		
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("loginInfos", loginInfos);
		body.put("redirectParameter", redirectParameter);
		
		return new ResponseEntity<Object>(body, responseHeaders, HttpStatus.UNAUTHORIZED);
	}

}
