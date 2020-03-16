package net.jmb.oidc_demo.model;

public class RessourceSecurisee {
	
	private final long id;
	private final String content;

	public RessourceSecurisee(long id, String content) {
		this.id = id;
		this.content = content;
	}

	public long getId() {
		return id;
	}

	public String getContent() {
		return content;
	}

}
