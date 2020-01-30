package jmb.example.controllers;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jmb.example.beans.RessourceSecuriseeBean;

@RestController
@RequestMapping("/secure")
public class RessourceSecuriseeController {
	
	private static final String template = "Holà mon collègue ! Vous êtes %s!";
	private final AtomicLong counter = new AtomicLong();

	@GetMapping("/bean")
	public RessourceSecuriseeBean greeting(@RequestParam(defaultValue = "mon ami") String name) {
		
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		if (principal instanceof UserDetails) {
		  username = ((UserDetails)principal).getUsername();
		} else {
		  username = principal.toString();
		}
		System.out.println("Identification user dans /secure/bean => " + username);
		
		return new RessourceSecuriseeBean(counter.incrementAndGet(), String.format(template, name));
	}

}
