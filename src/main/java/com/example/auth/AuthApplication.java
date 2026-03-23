package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Classe principale de l'application Spring Boot.
 *
 * @author Poun
 * @version 1.0
 */
@SpringBootApplication
public class AuthApplication {

    /**
     * Point d'entrée de l'application.
     *
     * @param args arguments du programme
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}