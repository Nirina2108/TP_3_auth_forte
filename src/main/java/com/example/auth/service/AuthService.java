package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.validator.PasswordPolicyValidator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service qui gere la logique d'authentification.
 * Il permet l'inscription, la connexion et la recuperation
 * de l'utilisateur a partir de son token.
 */
@Service
public class AuthService {

    /**
     * Repository pour acceder aux utilisateurs en base de donnees.
     */
    private final UserRepository userRepository;

    /**
     * Validateur de politique de mot de passe.
     */
    private final PasswordPolicyValidator passwordPolicyValidator;

    /**
     * Outil de chiffrement des mots de passe.
     */
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * Construit le service d'authentification.
     *
     * @param userRepository repository des utilisateurs
     */
    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordPolicyValidator = new PasswordPolicyValidator();
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Inscrit un nouvel utilisateur apres verification des champs
     * et validation du mot de passe.
     *
     * @param request donnees d'inscription
     * @return utilisateur enregistre
     * @throws RuntimeException si un champ obligatoire est vide
     *                          ou si le mot de passe est invalide
     */
    public User register(RegisterRequest request) {

        if (request.getName() == null || request.getName().isBlank()) {
            throw new RuntimeException("Name obligatoire");
        }

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new RuntimeException("Email obligatoire");
        }

        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new RuntimeException("Password obligatoire");
        }

        if (!passwordPolicyValidator.isValid(request.getPassword())) {
            throw new RuntimeException(
                    "Password invalide : minimum 12 caracteres, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractere special"
            );
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());

        String passwordHash = passwordEncoder.encode(request.getPassword());
        user.setPasswordHash(passwordHash);

        user.setToken(null);
        user.setCreatedAt(LocalDateTime.now());
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        return userRepository.save(user);
    }

    /**
     * Connecte un utilisateur.
     * Verifie les champs, controle le blocage temporaire,
     * compare le mot de passe et genere un token si la connexion reussit.
     *
     * @param request donnees de connexion
     * @return token de session genere
     * @throws RuntimeException si l'email ou le mot de passe est vide,
     *                          si l'utilisateur est introuvable,
     *                          si le compte est bloque
     *                          ou si les identifiants sont invalides
     */
    public String login(LoginRequest request) {

        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new RuntimeException("Email obligatoire");
        }

        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new RuntimeException("Mot de passe obligatoire");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Utilisateur introuvable"));

        if (user.getLockUntil() != null && user.getLockUntil().isAfter(LocalDateTime.now())) {
            throw new RuntimeException("Compte bloque temporairement. Reessayez plus tard");
        }

        boolean passwordOk = passwordEncoder.matches(request.getPassword(), user.getPasswordHash());

        if (!passwordOk) {
            int essais = user.getFailedAttempts() + 1;
            user.setFailedAttempts(essais);

            if (essais >= 5) {
                user.setLockUntil(LocalDateTime.now().plusMinutes(2));
            }

            userRepository.save(user);
            throw new RuntimeException("Identifiants invalides");
        }

        user.setFailedAttempts(0);
        user.setLockUntil(null);

        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);

        return token;
    }

    /**
     * Retourne l'utilisateur correspondant au token fourni.
     *
     * @param token token d'authentification
     * @return utilisateur associe au token
     * @throws RuntimeException si le token est vide ou invalide
     */
    public User getMe(String token) {

        if (token == null || token.isBlank()) {
            throw new RuntimeException("Token manquant");
        }

        return userRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalide"));
    }
}