package net.jmb.oidc_demo.controllers;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import net.jmb.oidc_demo.model.RessourceSecurisee;

@RestController
@RequestMapping("/secure")
public class RessourceSecuriseeController {
	
	private static final String template = "Holà mon collègue ! Vous êtes %s!";
	private final AtomicLong counter = new AtomicLong();
	private final Map<Long, RessourceSecurisee> listeRessourcesSecurisees = new ConcurrentHashMap<>();

	@GetMapping("/ressources/nouvelle")
	public RessourceSecurisee addResource(@RequestParam(defaultValue = "mon ami") String name) {
		
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		if (principal instanceof UserDetails) {
		  username = ((UserDetails)principal).getUsername();
		} else {
		  username = principal.toString();
		}
		System.out.println("Identification user dans chemin sécurisé /secure/**\n=> " + username);
		
		RessourceSecurisee bean = new RessourceSecurisee(counter.incrementAndGet(), String.format(template, name));
		listeRessourcesSecurisees.put(bean.getId(), bean);		
		return bean;
	}
	
	@GetMapping("/ressources/{id}")
	public RessourceSecurisee getResource(@PathVariable Long id) {
		
		RessourceSecurisee bean = listeRessourcesSecurisees.get(id);			
		return bean;
	}

}
