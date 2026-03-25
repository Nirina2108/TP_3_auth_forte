package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests simples du service AuthService.
 */
class AuthServiceSimpleTest {

    private UserRepository userRepository;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = Mockito.mock(UserRepository.class);
        authService = new AuthService(userRepository);
    }

    @Test
    void registerSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setEmail("test@gmail.com");
        request.setPassword("123");

        Mockito.when(userRepository.findByEmail("test@gmail.com"))
                .thenReturn(Optional.empty());

        Map<String, Object> response = authService.register(request);

        assertEquals("Inscription reussie", response.get("message"));
    }

    @Test
    void registerEmailExists() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Test");
        request.setEmail("test@gmail.com");
        request.setPassword("123");

        User user = new User();
        user.setEmail("test@gmail.com");

        Mockito.when(userRepository.findByEmail("test@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.register(request);

        assertEquals("Email deja utilise", response.get("message"));
    }

    @Test
    void loginSuccess() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@gmail.com");
        request.setPassword("123");

        User user = new User();
        user.setEmail("test@gmail.com");
        user.setPassword("123");

        Mockito.when(userRepository.findByEmail("test@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion reussie", response.get("message"));
    }

    @Test
    void loginWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@gmail.com");
        request.setPassword("999");

        User user = new User();
        user.setEmail("test@gmail.com");
        user.setPassword("123");

        Mockito.when(userRepository.findByEmail("test@gmail.com"))
                .thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Mot de passe incorrect", response.get("message"));
    }

    @Test
    void loginUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("unknown@gmail.com");
        request.setPassword("123");

        Mockito.when(userRepository.findByEmail("unknown@gmail.com"))
                .thenReturn(Optional.empty());

        Map<String, Object> response = authService.login(request);

        assertEquals("Utilisateur introuvable", response.get("message"));
    }
}