package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Contrôleur REST d'authentification.
 *
 * Routes disponibles :
 * - POST /api/auth/register
 * - POST /api/auth/login
 * - GET /api/auth/protected
 *
 * @author Poun
 * @version 1.0
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Clé utilisée pour les messages JSON.
     */
    private static final String KEY_MESSAGE = "message";

    /**
     * Préfixe Bearer utilisé dans l'en-tête Authorization.
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Service d'authentification.
     */
    private final AuthService authService;

    /**
     * Constructeur du contrôleur.
     *
     * @param authService service d'authentification
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Vérifie si une chaîne est vide.
     *
     * @param value valeur à tester
     * @return true si la valeur est nulle ou vide
     */
    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Extrait le token depuis l'en-tête Authorization.
     *
     * @param authorizationHeader en-tête Authorization
     * @return token extrait
     */
    private String extractToken(String authorizationHeader) {
        return authorizationHeader.replace(BEARER_PREFIX, "");
    }

    /**
     * Inscription d'un utilisateur.
     *
     * @param request données d'inscription
     * @return réponse JSON
     */
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    /**
     * Connexion d'un utilisateur.
     *
     * @param request données de connexion
     * @return réponse JSON avec token
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    /**
     * Route protégée.
     *
     * @param authorizationHeader en-tête Authorization
     * @return réponse d'accès
     */
    @GetMapping("/protected")
    public Map<String, Object> protectedRoute(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        if (isBlank(authorizationHeader)) {
            return Map.of(KEY_MESSAGE, "Token manquant");
        }

        String token = extractToken(authorizationHeader);
        return authService.accessProtectedData(token);
    }
}