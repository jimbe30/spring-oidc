package net.jmb.oidc_demo.controllers;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import net.jmb.oidc_demo.model.IdentityProviderRegistration;

@Controller
@CrossOrigin
public class AuthorizationController {
	
	@Autowired
	Map<String, IdentityProviderRegistration> idpRegistrations;

	@GetMapping("/login/discovery")
	@ResponseBody
	public Map<String, IdentityProviderRegistration> loginInfos() {
		return idpRegistrations;
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
	
	@RequestMapping("/login/{idp}")
	public void loginIdp(@PathVariable String idp, 
			@RequestParam("redirect_to") String redirectTo) {
		
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
				idpRegistrations.values().stream().map(
					idpRegistration -> {
						return idpRegistration.getAuthorizationPath();
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
		body.put("loginInfos", idpRegistrations);
		body.put("redirectParameter", redirectParameter);
		
		return new ResponseEntity<Object>(body, responseHeaders, HttpStatus.UNAUTHORIZED);
	}

}
