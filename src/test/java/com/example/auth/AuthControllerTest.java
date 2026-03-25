package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

/**
 * Tests de la classe AuthController.
 *
 * @author Poun
 * @version 1.0
 */
class AuthControllerTest {

    /**
     * Service simule.
     */
    private AuthService authService;

    /**
     * Controleur a tester.
     */
    private AuthController authController;

    /**
     * Preparation avant chaque test.
     */
    @BeforeEach
    void setUp() {
        authService = mock(AuthService.class);
        authController = new AuthController(authService);
    }

    /**
     * Verifie que register delegue bien au service.
     */
    @Test
    void shouldCallServiceRegister() {
        RegisterRequest request = new RegisterRequest();
        Map<String, Object> expectedResponse = Map.of("message", "Inscription reussie");

        when(authService.register(request)).thenReturn(expectedResponse);

        Map<String, Object> response = authController.register(request);

        assertEquals("Inscription reussie", response.get("message"));
    }

    /**
     * Verifie que login delegue bien au service.
     */
    @Test
    void shouldCallServiceLogin() {
        LoginRequest request = new LoginRequest();
        Map<String, Object> expectedResponse = Map.of("message", "Connexion reussie");

        when(authService.login(request)).thenReturn(expectedResponse);

        Map<String, Object> response = authController.login(request);

        assertEquals("Connexion reussie", response.get("message"));
    }

    /**
     * Verifie qu'un header absent retourne un message d'erreur.
     */
    @Test
    void shouldReturnErrorWhenAuthorizationHeaderIsMissing() {
        Map<String, Object> response = authController.protectedRoute(null);

        assertEquals("Token manquant", response.get("message"));
    }

    /**
     * Verifie qu'un header mal formate retourne un message d'erreur.
     */
    @Test
    void shouldReturnErrorWhenAuthorizationHeaderFormatIsInvalid() {
        Map<String, Object> response = authController.protectedRoute("abc123");

        assertEquals("Format du token invalide", response.get("message"));
    }

    /**
     * Verifie qu'un token Bearer est bien transmis au service.
     */
    @Test
    void shouldCallServiceWhenAuthorizationHeaderIsValid() {
        when(authService.accessProtectedData("abc123"))
                .thenReturn(Map.of("message", "Acces autorise"));

        Map<String, Object> response = authController.protectedRoute("Bearer abc123");

        verify(authService).accessProtectedData("abc123");
        assertEquals("Acces autorise", response.get("message"));
    }
}