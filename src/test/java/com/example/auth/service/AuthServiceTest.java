package com.example.auth.service;

import com.example.auth.AuthApplication;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

/**
 * Tests unitaires du service d'authentification.
 *
 * @author Poun
 * @version 1.0
 */
@SpringBootTest(classes = AuthApplication.class)
@ActiveProfiles("test")
public class AuthServiceTest {

    /**
     * Clé utilisée pour lire le message de la réponse.
     */
    private static final String KEY_MESSAGE = "message";

    /**
     * Message attendu pour une inscription réussie.
     */
    private static final String MSG_REGISTER_OK = "Inscription reussie";

    /**
     * Message attendu pour un email déjà utilisé.
     */
    private static final String MSG_EMAIL_USED = "Email deja utilise";

    /**
     * Message attendu pour un nom obligatoire.
     */
    private static final String MSG_NAME_REQUIRED = "Nom obligatoire";

    /**
     * Message attendu pour un email obligatoire.
     */
    private static final String MSG_EMAIL_REQUIRED = "Email obligatoire";

    /**
     * Message attendu pour un mot de passe obligatoire.
     */
    private static final String MSG_PASSWORD_REQUIRED = "Mot de passe obligatoire";

    /**
     * Message attendu pour une connexion réussie.
     */
    private static final String MSG_LOGIN_OK = "Connexion reussie";

    /**
     * Message attendu pour un mot de passe incorrect.
     */
    private static final String MSG_WRONG_PASSWORD = "Mot de passe incorrect";

    /**
     * Message attendu pour un utilisateur introuvable.
     */
    private static final String MSG_USER_NOT_FOUND = "Utilisateur introuvable";

    /**
     * Message attendu pour un accès refusé.
     */
    private static final String MSG_ACCESS_DENIED = "Acces refuse";

    /**
     * Message attendu pour un accès autorisé.
     */
    private static final String MSG_ACCESS_GRANTED = "Acces autorise";

    /**
     * Service d'authentification à tester.
     */
    @Autowired
    private AuthService authService;

    /**
     * Crée une requête d'inscription.
     *
     * @param name nom
     * @param email email
     * @param password mot de passe
     * @return requête d'inscription
     */
    private RegisterRequest buildRegisterRequest(String name, String email, String password) {
        RegisterRequest request = new RegisterRequest();
        request.setName(name);
        request.setEmail(email);
        request.setPassword(password);
        return request;
    }

    /**
     * Crée une requête de connexion.
     *
     * @param email email
     * @param password mot de passe
     * @return requête de connexion
     */
    private LoginRequest buildLoginRequest(String email, String password) {
        LoginRequest request = new LoginRequest();
        request.setEmail(email);
        request.setPassword(password);
        return request;
    }

    /**
     * Vérifie qu'une inscription valide fonctionne.
     */
    @Test
    void testRegisterSuccess() {
        RegisterRequest request = buildRegisterRequest("Poun", "poun@gmail.com", "123456");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals(MSG_REGISTER_OK, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un email déjà utilisé est refusé.
     */
    @Test
    void testRegisterDuplicateEmail() {
        RegisterRequest firstRequest = buildRegisterRequest("A", "dup@gmail.com", "123");
        RegisterRequest secondRequest = buildRegisterRequest("B", "dup@gmail.com", "456");

        authService.register(firstRequest);
        Map<String, Object> response = authService.register(secondRequest);

        Assertions.assertEquals(MSG_EMAIL_USED, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un nom vide est refusé.
     */
    @Test
    void testRegisterWithoutName() {
        RegisterRequest request = buildRegisterRequest("", "test@gmail.com", "123");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals(MSG_NAME_REQUIRED, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un email vide est refusé.
     */
    @Test
    void testRegisterWithoutEmail() {
        RegisterRequest request = buildRegisterRequest("Test", "", "123");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals(MSG_EMAIL_REQUIRED, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un mot de passe vide est refusé.
     */
    @Test
    void testRegisterWithoutPassword() {
        RegisterRequest request = buildRegisterRequest("Test", "test2@gmail.com", "");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals(MSG_PASSWORD_REQUIRED, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'une connexion valide fonctionne.
     */
    @Test
    void testLoginSuccess() {
        RegisterRequest registerRequest = buildRegisterRequest("User", "login@gmail.com", "123");
        authService.register(registerRequest);

        LoginRequest loginRequest = buildLoginRequest("login@gmail.com", "123");
        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals(MSG_LOGIN_OK, response.get(KEY_MESSAGE));
        Assertions.assertNotNull(response.get("token"));
    }

    /**
     * Vérifie qu'un mauvais mot de passe est refusé.
     */
    @Test
    void testLoginWrongPassword() {
        RegisterRequest registerRequest = buildRegisterRequest("User", "wrong@gmail.com", "123");
        authService.register(registerRequest);

        LoginRequest loginRequest = buildLoginRequest("wrong@gmail.com", "999");
        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals(MSG_WRONG_PASSWORD, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un utilisateur absent est refusé.
     */
    @Test
    void testLoginUserNotFound() {
        LoginRequest loginRequest = buildLoginRequest("unknown@gmail.com", "123");
        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals(MSG_USER_NOT_FOUND, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un accès protégé avec mauvais token est refusé.
     */
    @Test
    void testProtectedAccessInvalidToken() {
        Map<String, Object> response = authService.accessProtectedData("fake");

        Assertions.assertEquals(MSG_ACCESS_DENIED, response.get(KEY_MESSAGE));
    }

    /**
     * Vérifie qu'un accès protégé avec bon token est autorisé.
     */
    @Test
    void testProtectedAccessValidToken() {
        RegisterRequest registerRequest = buildRegisterRequest("Secure", "secure@gmail.com", "123");
        authService.register(registerRequest);

        LoginRequest loginRequest = buildLoginRequest("secure@gmail.com", "123");
        Map<String, Object> loginResponse = authService.login(loginRequest);

        String token = (String) loginResponse.get("token");
        Map<String, Object> protectedResponse = authService.accessProtectedData(token);

        Assertions.assertEquals(MSG_ACCESS_GRANTED, protectedResponse.get(KEY_MESSAGE));
        Assertions.assertEquals("Donnees protegees fragiles", protectedResponse.get("secret"));
    }
}