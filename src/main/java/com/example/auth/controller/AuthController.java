package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Controleur REST pour gerer l'authentification.
 * Il expose les endpoints pour :
 * - l'inscription
 * - la connexion
 * - la recuperation de l'utilisateur connecte
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Logger pour afficher les informations dans la console.
     */
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    /**
     * Service d'authentification contenant la logique metier.
     */
    private final AuthService authService;

    /**
     * Constructeur du controleur.
     *
     * @param authService service d'authentification
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint pour inscrire un nouvel utilisateur.
     *
     * @param request donnees d'inscription (nom, email, mot de passe)
     * @return reponse contenant un message, l'id et l'email de l'utilisateur
     */
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {

        logger.info("Tentative d'inscription pour {}", request.getEmail());

        User user = authService.register(request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User created");
        response.put("id", user.getId());
        response.put("email", user.getEmail());

        return response;
    }

    /**
     * Endpoint pour connecter un utilisateur.
     *
     * @param request donnees de connexion (email et mot de passe)
     * @return reponse contenant un message, le token et l'email
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {

        logger.info("Tentative de connexion pour {}", request.getEmail());

        String token = authService.login(request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Login success");
        response.put("token", token);
        response.put("email", request.getEmail());

        return response;
    }

    /**
     * Endpoint pour recuperer les informations de l'utilisateur connecte.
     *
     * @param authorizationHeader header contenant le token (Bearer token)
     * @return informations de l'utilisateur (id, email, date de creation)
     */
    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader("Authorization") String authorizationHeader) {

        logger.info("Acces a /api/auth/me");

        String token = authorizationHeader.replace("Bearer ", "");
        User user = authService.getMe(token);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());

        return response;
    }
}