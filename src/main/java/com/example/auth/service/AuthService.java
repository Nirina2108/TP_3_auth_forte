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

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordPolicyValidator = new PasswordPolicyValidator();
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

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

    public User getMe(String token) {

        if (token == null || token.isBlank()) {
            throw new RuntimeException("Token manquant");
        }

        return userRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token invalide"));
    }
}