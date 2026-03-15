package com.example.auth;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test simple du service d'authentification.
 */
@SpringBootTest
public class AuthServiceTest {

    @Autowired
    private AuthService authService;

    @Test
    void testRegisterAndLogin() {

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setEmail("test2@example.com");
        registerRequest.setPassword("1234");

        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test2@example.com");
        loginRequest.setPassword("1234");

        String token = authService.login(loginRequest);

        assertNotNull(token);
    }

    @Test
    void testLoginWithWrongPassword() {

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setEmail("test3@example.com");
        registerRequest.setPassword("1234");

        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test3@example.com");
        loginRequest.setPassword("9999");

        assertThrows(RuntimeException.class, () -> authService.login(loginRequest));
    }
}