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

    @Autowired
    private AuthService authService;

    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("123456");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Inscription reussie", response.get("message"));
    }

    @Test
    void testRegisterDuplicateEmail() {
        RegisterRequest r1 = new RegisterRequest();
        r1.setName("A");
        r1.setEmail("dup@gmail.com");
        r1.setPassword("123");

        RegisterRequest r2 = new RegisterRequest();
        r2.setName("B");
        r2.setEmail("dup@gmail.com");
        r2.setPassword("456");

        authService.register(r1);
        Map<String, Object> response = authService.register(r2);

        Assertions.assertEquals("Email deja utilise", response.get("message"));
    }

    @Test
    void testRegisterWithoutName() {
        RegisterRequest r = new RegisterRequest();
        r.setName("");
        r.setEmail("test@gmail.com");
        r.setPassword("123");

        Map<String, Object> response = authService.register(r);

        Assertions.assertEquals("Nom obligatoire", response.get("message"));
    }

    @Test
    void testRegisterWithoutEmail() {
        RegisterRequest r = new RegisterRequest();
        r.setName("Test");
        r.setEmail("");
        r.setPassword("123");

        Map<String, Object> response = authService.register(r);

        Assertions.assertEquals("Email obligatoire", response.get("message"));
    }

    @Test
    void testLoginSuccess() {
        RegisterRequest r = new RegisterRequest();
        r.setName("User");
        r.setEmail("login@gmail.com");
        r.setPassword("123");

        authService.register(r);

        LoginRequest login = new LoginRequest();
        login.setEmail("login@gmail.com");
        login.setPassword("123");

        Map<String, Object> response = authService.login(login);

        Assertions.assertEquals("Connexion reussie", response.get("message"));
    }

    @Test
    void testLoginWrongPassword() {
        RegisterRequest r = new RegisterRequest();
        r.setName("User");
        r.setEmail("wrong@gmail.com");
        r.setPassword("123");

        authService.register(r);

        LoginRequest login = new LoginRequest();
        login.setEmail("wrong@gmail.com");
        login.setPassword("999");

        Map<String, Object> response = authService.login(login);

        Assertions.assertEquals("Mot de passe incorrect", response.get("message"));
    }

    @Test
    void testProtectedAccessInvalidToken() {
        Map<String, Object> response = authService.accessProtectedData("fake");

        Assertions.assertEquals("Acces refuse", response.get("message"));
    }
}