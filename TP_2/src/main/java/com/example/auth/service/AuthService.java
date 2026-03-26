package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service contenant la logique métier de l'authentification.
 *
 * TP3 étape 1 :
 * - stockage réversible du secret utilisateur
 * - préparation du protocole HMAC + nonce
 * - login temporairement conservé en mode simple pour la transition
 *
 * Limite importante :
 * le stockage réversible est pédagogique et ne doit pas être considéré
 * comme une bonne pratique de production.
 *
 * @author Poun
 * @version 3.1
 */
@Service
public class AuthService {

    /**
     * Durée d'un token en minutes.
     */
    private static final int TOKEN_DURATION_MINUTES = 15;

    /**
     * Repository utilisateur.
     */
    private final UserRepository userRepository;

    /**
     * Service de chiffrement réversible.
     */
    private final PasswordCryptoService passwordCryptoService;

    /**
     * Validateur de mot de passe.
     */
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    /**
     * Constructeur du service.
     *
     * @param userRepository repository utilisateur
     * @param passwordCryptoService service de chiffrement
     */
    public AuthService(UserRepository userRepository, PasswordCryptoService passwordCryptoService) {
        this.userRepository = userRepository;
        this.passwordCryptoService = passwordCryptoService;
    }

    /**
     * Inscription d'un utilisateur.
     *
     * @param request données d'inscription
     * @return réponse simple
     */
    public Map<String, Object> register(RegisterRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getPassword() == null || !passwordPolicyValidator.isValid(request.getPassword())) {
            response.put("error", passwordPolicyValidator.getRulesMessage());
            return response;
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.put("error", "Email déjà utilisé");
            return response;
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPasswordEncrypted(passwordCryptoService.encrypt(request.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setToken(null);
        user.setTokenExpiresAt(null);

        userRepository.save(user);

        response.put("message", "Inscription réussie");
        return response;
    }

    /**
     * Connexion temporaire de transition.
     *
     * Pour cette étape 3.1, on garde encore une connexion simple afin de
     * vérifier que le projet reste fonctionnel après migration du stockage.
     * Le vrai protocole HMAC arrivera dans les étapes suivantes.
     *
     * @param request données de connexion
     * @return message + token ou erreur
     */
    public Map<String, Object> login(LoginRequest request) {
        Map<String, Object> response = new HashMap<>();

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put("error", "Utilisateur introuvable");
            return response;
        }

        String passwordPlain = passwordCryptoService.decrypt(user.getPasswordEncrypted());

        if (!passwordPlain.equals(request.getPassword())) {
            response.put("error", "Mot de passe incorrect");
            return response;
        }

        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(TOKEN_DURATION_MINUTES);

        user.setToken(token);
        user.setTokenExpiresAt(expiresAt);
        userRepository.save(user);

        response.put("message", "Connexion réussie");
        response.put("token", token);
        response.put("expiresAt", expiresAt);
        response.put("email", user.getEmail());

        return response;
    }

    /**
     * Retourne les informations de l'utilisateur connecté à partir du token.
     *
     * @param authorizationHeader header Authorization
     * @return informations utilisateur ou erreur
     */
    public Map<String, Object> getMe(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put("error", "Token manquant ou invalide");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put("error", "Utilisateur non trouvé pour ce token");
            return response;
        }

        if (user.getTokenExpiresAt() == null || user.getTokenExpiresAt().isBefore(LocalDateTime.now())) {
            response.put("error", "Token expiré ou invalide");
            return response;
        }

        response.put("id", user.getId());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());
        response.put("tokenExpiresAt", user.getTokenExpiresAt());

        return response;
    }

    /**
     * Déconnexion d'un utilisateur.
     *
     * @param authorizationHeader header Authorization
     * @return message de confirmation
     */
    public Map<String, Object> logout(String authorizationHeader) {
        Map<String, Object> response = new HashMap<>();

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            response.put("error", "Token manquant ou invalide");
            return response;
        }

        String token = authorizationHeader.substring(7);

        User user = userRepository.findByToken(token).orElse(null);

        if (user == null) {
            response.put("error", "Utilisateur non trouvé");
            return response;
        }

        user.setToken(null);
        user.setTokenExpiresAt(null);
        userRepository.save(user);

        response.put("message", "Déconnexion réussie");
        return response;
    }
}