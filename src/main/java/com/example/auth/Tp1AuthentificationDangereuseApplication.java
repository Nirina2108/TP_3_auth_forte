package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Classe principale de l'application Spring Boot.
 * Elle permet de demarrer le serveur et d'initialiser
 * tous les composants (controller, service, repository).
 */
@SpringBootApplication
public class Tp1AuthentificationDangereuseApplication {

	/**
	 * Methode principale pour lancer l'application.
	 *
	 * @param args arguments du programme
	 */
	public static void main(String[] args) {
		SpringApplication.run(Tp1AuthentificationDangereuseApplication.class, args);
	}
}