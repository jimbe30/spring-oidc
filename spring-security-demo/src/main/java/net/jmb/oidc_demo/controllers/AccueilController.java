package net.jmb.oidc_demo.controllers;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Arrays;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.jmb.oidc_demo.security.WebSecurityConfig;
import net.jmb.oidc_demo.security.WebSecurityConfig.OidcHttpConfig.AuthorizationRequestResolverWithParameters;
import springfox.documentation.annotations.ApiIgnore;

@Controller
public class AccueilController {

	@Autowired
	JwtDecoder jwtDecoder;

	String targetUrlParameter = WebSecurityConfig.TARGET_URL_PARAM;

	@GetMapping("/accueil")
	@ResponseBody
	public ResponseEntity<Object> accueil(
			@ApiIgnore @AuthenticationPrincipal OidcUser principal,
			@ApiIgnore HttpSession session, @ApiIgnore HttpServletRequest request, @ApiIgnore HttpServletResponse response,
			@RequestParam(value = "id_token", required = false) String idToken,
			@RequestHeader(value = "Authorization", required = false) String bearerToken
			
	) throws ServletException, IOException, URISyntaxException {

		String token = null;
		if (principal != null) {
			token = principal.getIdToken().getTokenValue();
		} else if (idToken != null) {
			token = idToken;
		} else if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			token = bearerToken.substring(7);
		}
		if (StringUtils.hasText(token)) {
			ResponseEntity<Object> responseEntity = null;
			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(token);

			try {
				JWT jwt = JWTParser.parse(token);

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
						responseEntity = new ResponseEntity<Object>(jwt.getJWTClaimsSet(), headers, HttpStatus.FOUND);
					}
				}
				if (responseEntity == null) {
					responseEntity = new ResponseEntity<Object>(jwt.getJWTClaimsSet(), headers, HttpStatus.OK);
				}
				session.invalidate();
				return responseEntity;
				
			} catch (ParseException e) {
				request.getRequestDispatcher("/error_401").forward(request, response);
				return null;
			}
		}

		return ResponseEntity.ok("Vous n'êtes pas encore identifié");

	}

}
