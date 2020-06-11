package net.jmb.oidc_demo.controllers;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import net.jmb.oidc_demo.security.WebSecurityConfig;
import net.jmb.oidc_demo.security.WebSecurityConfig.OidcHttpConfig.AuthorizationRequestResolverWithParameters;
import springfox.documentation.annotations.ApiIgnore;

@Controller
@RequestMapping("token")
public class TokenController {

	@Autowired
	JwtDecoder jwtDecoder;

	String targetUrlParameter = WebSecurityConfig.TARGET_URL_PARAM;

	@RequestMapping("/ok")
	@ResponseBody
	@ApiIgnore
	public ResponseEntity<Object> tokenResult(
			@AuthenticationPrincipal OidcUser principal, 
			HttpServletRequest request,	HttpServletResponse response, 
			@RequestParam(value = "id_token", required = false) String idToken,
			@RequestHeader(value = "Authorization", required = false) String bearerToken

	) throws ServletException, IOException, URISyntaxException {

		String token = "";
		if (principal != null) {
			token = principal.getIdToken().getTokenValue();
		}
		
		ResponseEntity<Object> responseEntity = null;
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(token);

		try {
			HttpSession session = request.getSession();

			StringBuffer queryParams = new StringBuffer();
			@SuppressWarnings("unchecked")
			Map<String, String[]> parameters = (Map<String, String[]>) session
					.getAttribute(AuthorizationRequestResolverWithParameters.SAVED_PARAMETERS_ATTR_NAME);

			if (parameters != null) {
				final StringBuffer tmpTargetUrl = new StringBuffer();
				parameters.forEach((paramKey, paramValues) -> {
					if (targetUrlParameter != null && paramKey.equals(targetUrlParameter)) {
						if (StringUtils.hasText(paramValues[0])) {
							tmpTargetUrl.append(paramValues[0].trim());
						}
					} else {
						Arrays.stream(paramValues).forEach(paramValue -> {
							queryParams.append(queryParams.length() > 0 ? "&" : "?")
									.append(paramKey + "=" + paramValue);
						});
					}
				});
				queryParams.append(queryParams.length() > 0 ? "&" : "?").append("token_type=Bearer")
						.append("&id_token=" + token);

				if (tmpTargetUrl.length() > 0) {
					String targetUrl = tmpTargetUrl.append(queryParams).toString();
					URI location = new URI(targetUrl);
					headers.setLocation(location);
					responseEntity = new ResponseEntity<Object>(null, headers, HttpStatus.FOUND);
				}
			}
			
			if (responseEntity == null) {
				JWTClaimsSet jwtClaimsSet = JWTParser.parse(token).getJWTClaimsSet();
				Map<String, Object> body = new HashMap<String, Object>();
				body.put("tokenValue", token);
				body.put("claims", jwtClaimsSet.getClaims());
				responseEntity = new ResponseEntity<Object>(body, HttpStatus.OK);
			}
			session.invalidate();
			return responseEntity;

		} catch (Exception e) {
			responseEntity = new ResponseEntity<Object>(e.getMessage(), HttpStatus.UNAUTHORIZED);
		}
		
		return responseEntity;
	}
	
	@PostMapping("/validate")
	@ResponseBody
	public ResponseEntity<Object> validateToken(
			HttpServletRequest request,	HttpServletResponse response, 
			@RequestParam(value = "id_token", required = false) String idToken,
			@RequestHeader(value = "Authorization", required = false) String bearerToken
	) throws ServletException, IOException, URISyntaxException {

		String token = "";
		if (idToken != null) {
			token = idToken;
		} else if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			token = bearerToken.substring(7);
		}
		ResponseEntity<Object> responseEntity;
		try {			
			Jwt jwt = jwtDecoder.decode(token);					
			responseEntity = new ResponseEntity<Object>(jwt, HttpStatus.OK);
		} catch (JwtException e) {
			responseEntity = new ResponseEntity<Object>(e.getMessage(), HttpStatus.UNAUTHORIZED);
		}
		return responseEntity;
	}

}
