package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Tests unitaires du service d'authentification.
 *
 * @author Poun
 * @version 2.4
 */
@SpringBootTest
@ActiveProfiles("test")
public class AuthServiceTest {

    /**
     * Service à tester.
     */
    @Autowired
    private AuthService authService;

    /**
     * Repository utilisateur.
     */
    @Autowired
    private UserRepository userRepository;

    /**
     * Nettoie la base avant chaque test.
     */
    @BeforeEach
    void cleanDatabase() {
        userRepository.deleteAll();
    }

    /**
     * Vérifie qu'une inscription valide fonctionne.
     */
    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("register1@gmail.com");
        request.setPassword("Bonjour123!A");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Inscription réussie", response.get("message"));
    }

    /**
     * Vérifie qu'un email déjà utilisé est refusé.
     */
    @Test
    void testRegisterDuplicateEmail() {
        RegisterRequest request1 = new RegisterRequest();
        request1.setName("Poun");
        request1.setEmail("duplicate1@gmail.com");
        request1.setPassword("Bonjour123!A");

        RegisterRequest request2 = new RegisterRequest();
        request2.setName("Poun2");
        request2.setEmail("duplicate1@gmail.com");
        request2.setPassword("Bonjour123!A");

        authService.register(request1);
        Map<String, Object> response = authService.register(request2);

        Assertions.assertEquals("Email déjà utilisé", response.get("error"));
    }

    /**
     * Vérifie qu'une connexion valide fonctionne.
     */
    @Test
    void testLoginSuccess() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("login1@gmail.com");
        registerRequest.setPassword("Bonjour123!A");

        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login1@gmail.com");
        loginRequest.setPassword("Bonjour123!A");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Connexion réussie", response.get("message"));
        Assertions.assertNotNull(response.get("token"));
    }

    /**
     * Vérifie qu'un mauvais mot de passe est refusé.
     */
    @Test
    void testLoginWrongPassword() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("login2@gmail.com");
        registerRequest.setPassword("Bonjour123!A");

        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login2@gmail.com");
        loginRequest.setPassword("Mauvais123!A");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Mot de passe incorrect", response.get("error"));
    }

    /**
     * Vérifie qu'après 5 mauvais essais, le compte est bloqué.
     */
    @Test
    void testAccountLockedAfterFiveFailedAttempts() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("lock1@gmail.com");
        registerRequest.setPassword("Bonjour123!A");

        authService.register(registerRequest);

        LoginRequest badLogin = new LoginRequest();
        badLogin.setEmail("lock1@gmail.com");
        badLogin.setPassword("FauxPassword123!");

        for (int i = 0; i < 5; i++) {
            authService.login(badLogin);
        }

        User user = userRepository.findByEmail("lock1@gmail.com").orElse(null);

        Assertions.assertNotNull(user);
        Assertions.assertNotNull(user.getLockUntil());
        Assertions.assertTrue(user.getLockUntil().isAfter(LocalDateTime.now()));
    }

    /**
     * Vérifie qu'un compte bloqué ne peut pas se connecter même avec le bon mot de passe.
     */
    @Test
    void testBlockedAccountCannotLogin() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("lock2@gmail.com");
        registerRequest.setPassword("Bonjour123!A");

        authService.register(registerRequest);

        User user = userRepository.findByEmail("lock2@gmail.com").orElse(null);
        Assertions.assertNotNull(user);

        user.setLockUntil(LocalDateTime.now().plusMinutes(2));
        userRepository.save(user);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("lock2@gmail.com");
        loginRequest.setPassword("Bonjour123!A");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Compte bloqué temporairement. Réessayez plus tard.", response.get("error"));
    }
}