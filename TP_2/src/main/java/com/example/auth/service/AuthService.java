package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service contenant la logique métier de l'authentification.
 *
 * TP2 :
 * - politique de mot de passe
 * - stockage BCrypt
 * - protection anti brute force
 *
 * @author Poun
 * @version 2.4
 */
@Service
public class AuthService {

    /**
     * Nombre maximum d'échecs autorisés.
     */
    private static final int MAX_FAILED_ATTEMPTS = 5;

    /**
     * Durée du blocage en minutes.
     */
    private static final int LOCK_DURATION_MINUTES = 2;

    /**
     * Repository utilisateur.
     */
    private final UserRepository userRepository;

    /**
     * Validateur de mot de passe.
     */
    private final PasswordPolicyValidator passwordPolicyValidator = new PasswordPolicyValidator();

    /**
     * Encodeur BCrypt pour le hash du mot de passe.
     */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Constructeur du service.
     *
     * @param userRepository repository utilisateur
     */
    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
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
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        userRepository.save(user);

        response.put("message", "Inscription réussie");
        return response;
    }

    /**
     * Connexion d'un utilisateur.
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

        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            response.put("error", "Compte bloqué temporairement. Réessayez plus tard.");
            return response;
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            int newFailedAttempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(newFailedAttempts);

            if (newFailedAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
                user.setFailedAttempts(0);
                userRepository.save(user);
                response.put("error", "Compte bloqué temporairement. Réessayez plus tard.");
                return response;
            }

            userRepository.save(user);
            response.put("error", "Mot de passe incorrect");
            return response;
        }

        user.setFailedAttempts(0);
        user.setLockUntil(null);

        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);

        response.put("message", "Connexion réussie");
        response.put("token", token);
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

        response.put("id", user.getId());
        response.put("name", user.getName());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());

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
        userRepository.save(user);

        response.put("message", "Déconnexion réussie");
        return response;
    }
}