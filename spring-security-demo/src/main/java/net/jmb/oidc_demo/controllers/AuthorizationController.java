package net.jmb.oidc_demo.controllers;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import net.jmb.oidc_demo.model.IdentityProviderRegistration;
import net.jmb.oidc_demo.security.WebSecurityConfig;
import springfox.documentation.annotations.ApiIgnore;

@Controller
@CrossOrigin
public class AuthorizationController {
	
	@Autowired
	Map<String, IdentityProviderRegistration> idpRegistrations;
	final String redirectParameter = WebSecurityConfig.TARGET_URL_PARAM;

	@GetMapping("/login/infos")
	@ResponseBody
	public Map<String, Object> loginInfos() {
		
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("loginInfos", idpRegistrations);
		body.put("redirectParameter", redirectParameter);
		return body;
	}

	@RequestMapping("/login")
	@ApiIgnore()
	public ModelAndView login(HttpServletRequest request,
			@RequestParam(value = redirectParameter, required = false) String redirectTo) {

		if (StringUtils.isEmpty(redirectTo)) {
			redirectTo = request.getHeader("Referer");
		}
		Map<String, String> body = null;
		if (StringUtils.hasText(redirectTo)) {
			body = new HashMap<String, String>();
			body.put(redirectParameter, redirectParameter + "=" + redirectTo);
		}
		return new ModelAndView("loginPage", body);
	}
	
	// http://localhost:6969/login/keycloak?redirect_to=http://localhost:6969/accueil
	@RequestMapping(path = "/login/{idp}", method = {RequestMethod.GET, RequestMethod.POST})
	public void loginIdp(
			HttpServletResponse response, 
			HttpServletRequest request,	
			@PathVariable String idp,
			@RequestParam(value = redirectParameter, required = false) String redirectTo) 
					throws ServletException, IOException, URISyntaxException {
		
		String authorizationPath = null;
		IdentityProviderRegistration idpRegistration = this.idpRegistrations.get(idp);
		if (idpRegistration != null) {
			authorizationPath = idpRegistration.getAuthorizationPath();
		}
		if (authorizationPath != null) {
			if (redirectTo != null) {
				authorizationPath += "?" + redirectParameter + "=" + redirectTo;
			}
			response.sendRedirect(request.getContextPath() + authorizationPath);
		} else {
			erreur401();
		}
	}
	
	@GetMapping("/error_401")
	public HttpEntity<Object> erreur401() throws URISyntaxException {				
		return erreur401(null);
	}

	@GetMapping("/error_401/{appName}")
	public HttpEntity<Object> erreur401(@PathVariable(required = false) String appName) throws URISyntaxException {
		
		HttpHeaders responseHeaders = new HttpHeaders();
		
		StringBuffer wwwAuthenticate = new StringBuffer("Bearer ");
		if (appName != null) {
			wwwAuthenticate.append("realm=\"" + appName + "\", ");
		}
		wwwAuthenticate
			.append("authorization-path=\"")
			.append(idpRegistrations.values().stream()
				.map(idpRegistration -> idpRegistration.getAuthorizationPath())
				.collect(Collectors.joining(", ")))
			.append("\", redirect-parameter=\"")
			.append(redirectParameter)
			.append("\"");
		responseHeaders.set("www-authenticate", wwwAuthenticate.toString());
		
		Map<String, Object> body = loginInfos();		
		HttpEntity<Object> response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(responseHeaders).body(body);
		return response;
	}

}
