package net.jmb.oidc.controllers;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.jmb.oidc.security.WebSecurityConfig;

@Controller
public class AccueilController {

	String targetUrlParameter = WebSecurityConfig.TARGET_URL_PARAM;

	@GetMapping("/accueil")
	@ResponseBody
	public ResponseEntity<Object> accueil(
			@AuthenticationPrincipal OidcUser principal,
			HttpSession session, HttpServletRequest request, HttpServletResponse response,
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
