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
 * Controller REST pour l'authentification.
 *
 * TP3 :
 * cette version prépare la transition vers une preuve HMAC signée,
 * tout en gardant temporairement les endpoints existants.
 *
 * @author Poun
 * @version 3.1
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Service d'authentification.
     */
    private final AuthService authService;

    /**
     * Constructeur du controller.
     *
     * @param authService service d'authentification
     */
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint d'inscription.
     *
     * @param request données d'inscription
     * @return réponse simple
     */
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    /**
     * Endpoint de connexion.
     *
     * Étape transitoire :
     * le vrai protocole HMAC sera branché ensuite sur ce même endpoint.
     *
     * @param request données de connexion
     * @return message + token
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        return authService.login(request);
    }

    /**
     * Endpoint pour récupérer l'utilisateur connecté.
     *
     * @param authorizationHeader header Authorization
     * @return informations utilisateur
     */
    @GetMapping("/me")
    public Map<String, Object> me(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        return authService.getMe(authorizationHeader);
    }

    /**
     * Endpoint de déconnexion.
     *
     * @param authorizationHeader header Authorization
     * @return message de déconnexion
     */
    @PostMapping("/logout")
    public Map<String, Object> logout(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        return authService.logout(authorizationHeader);
    }
}