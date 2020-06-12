<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
	content="width=device-width, initial-scale=1, shrink-to-fit=no">
<meta name="description" content="">
<meta name="author" content="">
<title>Please sign in</title>
<link
	href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css"
	rel="stylesheet"
>
<link
	href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css"/>
</head>
<body>
	<div class="container">
		<h2 class="form-signin-heading"> Connexion sécurisée </h2>
		<h5>Choisissez un serveur d'authentification OpenID Connect</h5>

		<table class="table table-striped">
			<tr>
				<td><a href="/oauth2/authorization/google">Google</a></td>
			</tr>
			<tr>
				<td><a href="/oauth2/authorization/keycloak?${redirect_to}">Keycloak</a></td>
			</tr>
		</table>

	</div>
</body>
</html>