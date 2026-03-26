package com.example.auth.service;

import com.example.auth.AuthApplication;
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
 * Tests du service d'authentification pour le TP3.
 *
 * Cette version est adaptée à l'étape 3.2 :
 * - inscription avec mot de passe chiffré réversible
 * - login au nouveau format HMAC
 * - plus de mot de passe direct dans LoginRequest
 *
 * @author Poun
 * @version 3.2
 */
@SpringBootTest(classes = AuthApplication.class)
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
     * Nettoyage avant chaque test.
     */
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    /**
     * Teste une inscription valide.
     */
    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Inscription réussie", response.get("message"));
        Assertions.assertTrue(userRepository.findByEmail("poun@gmail.com").isPresent());
    }

    /**
     * Teste une inscription avec email déjà utilisé.
     */
    @Test
    void testRegisterDuplicateEmail() {
        RegisterRequest first = new RegisterRequest();
        first.setName("Poun");
        first.setEmail("poun@gmail.com");
        first.setPassword("Azerty1234!@");
        authService.register(first);

        RegisterRequest second = new RegisterRequest();
        second.setName("Poun2");
        second.setEmail("poun@gmail.com");
        second.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(second);

        Assertions.assertEquals("Email déjà utilisé", response.get("error"));
    }

    /**
     * Teste une inscription avec mot de passe invalide.
     */
    @Test
    void testRegisterWeakPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("123");

        Map<String, Object> response = authService.register(request);

        Assertions.assertNotNull(response.get("error"));
    }

    /**
     * Teste une connexion valide au format TP3.
     */
    @Test
    void testLoginSuccess() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@!");
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("poun@gmail.com");
        loginRequest.setNonce("test-nonce-1");
        loginRequest.setTimestamp(System.currentTimeMillis() / 1000);
        loginRequest.setHmac("fake-hmac");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Format TP3 reçu, vérification HMAC à brancher en v3.3", response.get("message"));
        Assertions.assertEquals("poun@gmail.com", response.get("email"));
        Assertions.assertEquals("test-nonce-1", response.get("nonce"));
        Assertions.assertNotNull(response.get("timestamp"));
        Assertions.assertEquals("fake-hmac", response.get("hmac"));
    }

    /**
     * Teste une connexion avec utilisateur introuvable.
     */
    @Test
    void testLoginUserNotFound() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("inconnu@gmail.com");
        loginRequest.setNonce("test-nonce-2");
        loginRequest.setTimestamp(System.currentTimeMillis() / 1000);
        loginRequest.setHmac("fake-hmac");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Utilisateur introuvable", response.get("error"));
    }

    /**
     * Teste une connexion sans nonce.
     */
    @Test
    void testLoginWithoutNonce() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@!");
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("poun@gmail.com");
        loginRequest.setTimestamp(System.currentTimeMillis() / 1000);
        loginRequest.setHmac("fake-hmac");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Nonce obligatoire", response.get("error"));
    }

    /**
     * Teste une connexion sans timestamp.
     */
    @Test
    void testLoginWithoutTimestamp() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@!");
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("poun@gmail.com");
        loginRequest.setNonce("test-nonce-3");
        loginRequest.setHmac("fake-hmac");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Timestamp obligatoire", response.get("error"));
    }

    /**
     * Teste une connexion sans HMAC.
     */
    @Test
    void testLoginWithoutHmac() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@!");
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("poun@gmail.com");
        loginRequest.setNonce("test-nonce-4");
        loginRequest.setTimestamp(System.currentTimeMillis() / 1000);

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("HMAC obligatoire", response.get("error"));
    }

    /**
     * Teste la récupération du profil avec token inconnu.
     *
     * En v3.2, le login n'émet pas encore de vrai token.
     */
    @Test
    void testGetMeWithUnknownToken() {
        Map<String, Object> response = authService.getMe("Bearer token-inconnu");

        Assertions.assertEquals("Utilisateur non trouvé pour ce token", response.get("error"));
    }

    /**
     * Teste getMe sans header Authorization valide.
     */
    @Test
    void testGetMeWithoutToken() {
        Map<String, Object> response = authService.getMe(null);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    /**
     * Teste getMe avec token expiré.
     */
    @Test
    void testGetMeWithExpiredToken() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@");
        authService.register(registerRequest);

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        user.setToken("token-expire");
        user.setTokenExpiresAt(LocalDateTime.now().minusMinutes(1));
        userRepository.save(user);

        Map<String, Object> response = authService.getMe("Bearer token-expire");

        Assertions.assertEquals("Token expiré ou invalide", response.get("error"));
    }

    /**
     * Teste la déconnexion avec token valide préparé manuellement.
     *
     * En v3.2, le login ne crée pas encore de token final.
     */
    @Test
    void testLogoutSuccess() {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("Poun");
        registerRequest.setEmail("poun@gmail.com");
        registerRequest.setPassword("Azerty1234!@");
        authService.register(registerRequest);

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        user.setToken("token-valide");
        user.setTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        Map<String, Object> logoutResponse = authService.logout("Bearer token-valide");

        Assertions.assertEquals("Déconnexion réussie", logoutResponse.get("message"));

        User updatedUser = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        Assertions.assertNull(updatedUser.getToken());
        Assertions.assertNull(updatedUser.getTokenExpiresAt());
    }

    /**
     * Teste la déconnexion sans header Authorization valide.
     */
    @Test
    void testLogoutWithoutToken() {
        Map<String, Object> response = authService.logout(null);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    /**
     * Teste la déconnexion avec token inconnu.
     */
    @Test
    void testLogoutWithUnknownToken() {
        Map<String, Object> response = authService.logout("Bearer token-inconnu");

        Assertions.assertEquals("Utilisateur non trouvé", response.get("error"));
    }
}