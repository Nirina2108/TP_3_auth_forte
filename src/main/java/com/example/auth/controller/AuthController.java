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
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return Map.of("message", "Token manquant");
        }

        String token = authorizationHeader.replace("Bearer ", "");
        return authService.accessProtectedData(token);
    }
}