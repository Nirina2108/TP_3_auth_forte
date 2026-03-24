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
     * Clé utilisée pour les messages des réponses.
     */
    private static final String KEY_MESSAGE = "message";

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
     * Vérifie si une chaîne est vide.
     *
     * @param valeur valeur à tester
     * @return true si la valeur est nulle ou vide
     */
    private boolean estVide(String valeur) {
        return valeur == null || valeur.isBlank();
    }

    /**
     * Inscrit un utilisateur.
     *
     * @param request données d'inscription
     * @return réponse avec message et utilisateur
     */
    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (estVide(request.getName())) {
            response.put(KEY_MESSAGE, "Nom obligatoire");
            return response;
        }

        if (estVide(request.getEmail())) {
            response.put(KEY_MESSAGE, "Email obligatoire");
            return response;
        }

        if (estVide(request.getPassword())) {
            response.put(KEY_MESSAGE, "Mot de passe obligatoire");
            return response;
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.put(KEY_MESSAGE, "Email deja utilise");
            return response;
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());

        userRepository.save(user);

        response.put(KEY_MESSAGE, "Inscription reussie");
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

        if (estVide(request.getEmail())) {
            response.put(KEY_MESSAGE, "Email obligatoire");
            return response;
        }

        if (estVide(request.getPassword())) {
            response.put(KEY_MESSAGE, "Mot de passe obligatoire");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put(KEY_MESSAGE, "Utilisateur introuvable");
            return response;
        }

        if (!user.getPassword().equals(request.getPassword())) {
            response.put(KEY_MESSAGE, "Mot de passe incorrect");
            return response;
        }

        String token = UUID.randomUUID().toString();
        tokens.put(token, user.getId());

        response.put(KEY_MESSAGE, "Connexion reussie");
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
            response.put(KEY_MESSAGE, "Acces refuse");
            return response;
        }

        response.put(KEY_MESSAGE, "Acces autorise");
        response.put("secret", "Donnees protegees fragiles");

        return response;
    }
}