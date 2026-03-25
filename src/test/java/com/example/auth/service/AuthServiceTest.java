package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.util.HmacUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires du service AuthService.
 *
 * @author Poun
 * @version 1.0
 */
class AuthServiceTest {

    /**
     * Repository utilisateur mocké.
     */
    private UserRepository userRepository;

    /**
     * Repository nonce mocké.
     */
    private AuthNonceRepository authNonceRepository;

    /**
     * Service testé.
     */
    private AuthService authService;

    /**
     * Préparation avant chaque test.
     */
    @BeforeEach
    void setUp() {
        userRepository = Mockito.mock(UserRepository.class);
        authNonceRepository = Mockito.mock(AuthNonceRepository.class);
        authService = new AuthService(userRepository, authNonceRepository);
    }

    /**
     * Vérifie qu'une inscription fonctionne.
     */
    @Test
    void registerSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Ikalo");
        request.setEmail("ikalo@gmail.com");
        request.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.empty());

        Map<String, Object> response = authService.register(request);

        assertEquals("Inscription reussie", response.get("message"));
        assertNotNull(response.get("user"));
    }

    /**
     * Vérifie qu'une inscription échoue si l'email existe déjà.
     */
    @Test
    void registerDuplicateEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Ikalo");
        request.setEmail("ikalo@gmail.com");
        request.setPassword("123456");

        User existingUser = new User();
        existingUser.setEmail("ikalo@gmail.com");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(existingUser));

        Map<String, Object> response = authService.register(request);

        assertEquals("Email deja utilise", response.get("message"));
    }

    /**
     * Vérifie qu'une inscription échoue si le nom est vide.
     */
    @Test
    void registerWithoutName() {
        RegisterRequest request = new RegisterRequest();
        request.setName("");
        request.setEmail("ikalo@gmail.com");
        request.setPassword("123456");

        Map<String, Object> response = authService.register(request);

        assertEquals("Nom obligatoire", response.get("message"));
    }

    /**
     * Vérifie qu'une inscription échoue si l'email est vide.
     */
    @Test
    void registerWithoutEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Ikalo");
        request.setEmail("");
        request.setPassword("123456");

        Map<String, Object> response = authService.register(request);

        assertEquals("Email obligatoire", response.get("message"));
    }

    /**
     * Vérifie qu'une inscription échoue si le mot de passe est vide.
     */
    @Test
    void registerWithoutPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Ikalo");
        request.setEmail("ikalo@gmail.com");
        request.setPassword("");

        Map<String, Object> response = authService.register(request);

        assertEquals("Mot de passe obligatoire", response.get("message"));
    }

    /**
     * Vérifie le format du message signé.
     */
    @Test
    void buildSignedMessageWorks() {
        String result = authService.buildSignedMessage(
                "ikalo@gmail.com",
                "nonce123",
                123456789L
        );

        assertEquals("ikalo@gmail.com:nonce123:123456789", result);
    }

    /**
     * Vérifie un login classique valide.
     */
    @Test
    void loginWithPasswordSuccess() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setPassword("123456");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion reussie", response.get("message"));
        assertNotNull(response.get("token"));
    }

    /**
     * Vérifie un login classique avec mauvais mot de passe.
     */
    @Test
    void loginWithPasswordWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setPassword("999");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Mot de passe incorrect", response.get("message"));
    }

    /**
     * Vérifie un login avec utilisateur inconnu.
     */
    @Test
    void loginUnknownUser() {
        LoginRequest request = new LoginRequest();
        request.setEmail("unknown@gmail.com");
        request.setPassword("123456");

        Mockito.when(userRepository.findByEmail("unknown@gmail.com"))
                .thenReturn(Optional.empty());

        Map<String, Object> response = authService.login(request);

        assertEquals("Utilisateur introuvable", response.get("message"));
    }

    /**
     * Vérifie un login HMAC valide.
     */
    @Test
    void loginWithHmacSuccess() {
        long timestamp = System.currentTimeMillis() / 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setNonce("nonce-hmac-ok");
        request.setTimestamp(timestamp);

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        String message = authService.buildSignedMessage(
                request.getEmail(),
                request.getNonce(),
                request.getTimestamp()
        );

        request.setHmac(HmacUtils.generateHmac("123456", message));

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));
        Mockito.when(authNonceRepository.existsByUserAndNonce(user, "nonce-hmac-ok"))
                .thenReturn(false);

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion securisee reussie", response.get("message"));
        assertNotNull(response.get("token"));
    }

    /**
     * Vérifie un login HMAC invalide.
     */
    @Test
    void loginWithHmacInvalid() {
        long timestamp = System.currentTimeMillis() / 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setNonce("nonce-hmac-ko");
        request.setTimestamp(timestamp);
        request.setHmac("hmac-invalide");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));
        Mockito.when(authNonceRepository.existsByUserAndNonce(user, "nonce-hmac-ko"))
                .thenReturn(false);

        Map<String, Object> response = authService.login(request);

        assertEquals("Hmac invalide", response.get("message"));
    }

    /**
     * Vérifie un timestamp expiré.
     */
    @Test
    void loginWithExpiredTimestamp() {
        long timestamp = (System.currentTimeMillis() / 1000) - 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setNonce("nonce-expire");
        request.setTimestamp(timestamp);
        request.setHmac("test");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Timestamp invalide ou expire", response.get("message"));
    }

    /**
     * Vérifie un nonce déjà utilisé.
     */
    @Test
    void loginWithUsedNonce() {
        long timestamp = System.currentTimeMillis() / 1000;

        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setNonce("nonce-used");
        request.setTimestamp(timestamp);
        request.setHmac("test");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));
        Mockito.when(authNonceRepository.existsByUserAndNonce(user, "nonce-used"))
                .thenReturn(true);

        Map<String, Object> response = authService.login(request);

        assertEquals("Nonce deja utilise (attaque rejeu)", response.get("message"));
    }

    /**
     * Vérifie qu'un token valide donne accès à la route protégée.
     */
    @Test
    void protectedAccessWithValidToken() {
        LoginRequest request = new LoginRequest();
        request.setEmail("ikalo@gmail.com");
        request.setPassword("123456");

        User user = new User();
        user.setId(1L);
        user.setEmail("ikalo@gmail.com");
        user.setPassword("123456");

        Mockito.when(userRepository.findByEmail("ikalo@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> loginResponse = authService.login(request);
        String token = (String) loginResponse.get("token");

        Map<String, Object> protectedResponse = authService.accessProtectedData(token);

        assertEquals("Acces autorise", protectedResponse.get("message"));
        assertEquals("Donnees protegees fragiles", protectedResponse.get("secret"));
    }

    /**
     * Vérifie qu'un token invalide est refusé.
     */
    @Test
    void protectedAccessWithInvalidToken() {
        Map<String, Object> response = authService.accessProtectedData("token-invalide");

        assertEquals("Acces refuse", response.get("message"));
    }
}