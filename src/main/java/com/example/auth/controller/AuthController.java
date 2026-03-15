package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {

        logger.info("Tentative d'inscription pour {}", request.getEmail());

        User user = authService.register(request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User created");
        response.put("id", user.getId());
        response.put("email", user.getEmail());

        return response;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {

        logger.info("Tentative de connexion pour {}", request.getEmail());

        String token = authService.login(request);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Login success");
        response.put("token", token);
        response.put("email", request.getEmail());

        return response;
    }

    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader("Authorization") String authorizationHeader) {

        logger.info("Acces a /api/auth/me");

        String token = authorizationHeader.replace("Bearer ", "");
        User user = authService.getMe(token);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("email", user.getEmail());
        response.put("createdAt", user.getCreatedAt());

        return response;
    }
}