package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service contenant la logique métier de l'authentification.
 *
 * Version fragile :
 * - mot de passe stocké en clair
 * - token simple simulé
 *
 * @author Poun
 * @version 1.0
 */
@Service
public class AuthService {

    /**
     * Repository utilisateur.
     */
    private final UserRepository userRepository;

    /**
     * Stockage simple des tokens générés.
     */
    private final Map<String, Long> tokens = new HashMap<>();

    /**
     * Constructeur du service.
     *
     * @param userRepository repository utilisateur
     */
    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un utilisateur.
     *
     * @param request données d'inscription
     * @return réponse avec message et utilisateur
     */
    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getName() == null || request.getName().isBlank()) {
            response.put("message", "Nom obligatoire");
            return response;
        }

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            response.put("message", "Email obligatoire");
            return response;
        }

        if (request.getPassword() == null || request.getPassword().isBlank()) {
            response.put("message", "Mot de passe obligatoire");
            return response;
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.put("message", "Email deja utilise");
            return response;
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());

        userRepository.save(user);

        response.put("message", "Inscription reussie");
        response.put("user", user);

        return response;
    }

    /**
     * Connecte un utilisateur.
     *
     * @param request données de connexion
     * @return réponse avec message et token
     */
    public Map<String, Object> login(LoginRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            response.put("message", "Email obligatoire");
            return response;
        }

        if (request.getPassword() == null || request.getPassword().isBlank()) {
            response.put("message", "Mot de passe obligatoire");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put("message", "Utilisateur introuvable");
            return response;
        }

        if (!user.getPassword().equals(request.getPassword())) {
            response.put("message", "Mot de passe incorrect");
            return response;
        }

        String token = UUID.randomUUID().toString();
        tokens.put(token, user.getId());

        response.put("message", "Connexion reussie");
        response.put("token", token);

        return response;
    }

    /**
     * Vérifie si un token est valide.
     *
     * @param token token à vérifier
     * @return true si le token existe
     */
    public boolean isTokenValid(String token) {
        return tokens.containsKey(token);
    }

    /**
     * Permet d'accéder à une ressource protégée.
     *
     * @param token token utilisateur
     * @return réponse d'accès
     */
    public Map<String, Object> accessProtectedData(String token) {
        Map<String, Object> response = new HashMap<>();

        if (!isTokenValid(token)) {
            response.put("message", "Acces refuse");
            return response;
        }

        response.put("message", "Acces autorise");
        response.put("secret", "Donnees protegees fragiles");

        return response;
    }
}