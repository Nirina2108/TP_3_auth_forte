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
 * TP3 étape 3.2 :
 * - stockage réversible du secret utilisateur
 * - préparation du format HMAC côté client
 * - la vérification serveur complète arrivera en 3.3
 *
 * @author Poun
 * @version 3.2
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
     * Constructeur.
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
     * Connexion au nouveau format TP3.
     *
     * À l'étape 3.2, on reçoit déjà :
     * - email
     * - nonce
     * - timestamp
     * - hmac
     *
     * La vérification complète HMAC côté serveur sera faite en 3.3.
     *
     * @param request requête de login TP3
     * @return réponse temporaire de transition
     */
    public Map<String, Object> login(LoginRequest request) {
        Map<String, Object> response = new HashMap<>();

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            response.put("error", "Email obligatoire");
            return response;
        }

        if (request.getNonce() == null || request.getNonce().isBlank()) {
            response.put("error", "Nonce obligatoire");
            return response;
        }

        if (request.getTimestamp() <= 0) {
            response.put("error", "Timestamp obligatoire");
            return response;
        }

        if (request.getHmac() == null || request.getHmac().isBlank()) {
            response.put("error", "HMAC obligatoire");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null) {
            response.put("error", "Utilisateur introuvable");
            return response;
        }

        response.put("message", "Format TP3 reçu, vérification HMAC à brancher en v3.3");
        response.put("email", request.getEmail());
        response.put("nonce", request.getNonce());
        response.put("timestamp", request.getTimestamp());
        response.put("hmac", request.getHmac());

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

    /**
     * Émet un token simple temporaire.
     *
     * Cette méthode sera utilisée à partir de la vraie validation HMAC.
     *
     * @param user utilisateur authentifié
     * @return réponse contenant token et expiration
     */
    public Map<String, Object> issueToken(User user) {
        Map<String, Object> response = new HashMap<>();

        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(TOKEN_DURATION_MINUTES);

        user.setToken(token);
        user.setTokenExpiresAt(expiresAt);
        userRepository.save(user);

        response.put("message", "Connexion réussie");
        response.put("accessToken", token);
        response.put("expiresAt", expiresAt);
        response.put("email", user.getEmail());

        return response;
    }
}