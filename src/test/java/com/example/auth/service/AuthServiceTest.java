package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests de la classe AuthService.
 *
 * @author Poun
 * @version 1.0
 */
class AuthServiceTest {

    /**
     * Repository simule.
     */
    private UserRepository userRepository;

    /**
     * Service a tester.
     */
    private AuthService authService;

    /**
     * Encodeur utilise pour preparer un mot de passe hashé.
     */
    private BCryptPasswordEncoder passwordEncoder;

    /**
     * Preparation avant chaque test.
     */
    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        authService = new AuthService(userRepository);
        passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Verifie que l'inscription echoue si le nom est vide.
     */
    @Test
    void shouldReturnErrorWhenNameIsMissing() {
        RegisterRequest request = new RegisterRequest();
        request.setName("");
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        Map<String, Object> response = authService.register(request);

        assertEquals("Nom obligatoire", response.get("message"));
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe est trop faible.
     */
    @Test
    void shouldReturnErrorWhenPasswordIsWeak() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("abc");

        Map<String, Object> response = authService.register(request);

        assertEquals("Mot de passe trop faible", response.get("message"));
    }

    /**
     * Verifie que l'inscription echoue si l'email existe deja.
     */
    @Test
    void shouldReturnErrorWhenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(new User()));

        Map<String, Object> response = authService.register(request);

        assertEquals("Email deja utilise", response.get("message"));
    }

    /**
     * Verifie qu'une inscription valide fonctionne et que
     * le mot de passe est hashé avant sauvegarde.
     */
    @Test
    void shouldRegisterUserWithHashedPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User savedUser = invocation.getArgument(0);
            savedUser.setId(1L);
            return savedUser;
        });

        Map<String, Object> response = authService.register(request);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();

        assertEquals("Inscription reussie", response.get("message"));
        assertNotEquals("MotDePasse1@", savedUser.getPassword());
        assertTrue(savedUser.getPassword().startsWith("$2"));
    }

    /**
     * Verifie que la connexion echoue si l'utilisateur n'existe pas.
     */
    @Test
    void shouldReturnErrorWhenUserIsNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.login(request);

        assertEquals("Utilisateur introuvable", response.get("message"));
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est incorrect.
     */
    @Test
    void shouldReturnErrorWhenPasswordIsIncorrect() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword(passwordEncoder.encode("AutreMotDePasse1@"));

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Mot de passe incorrect", response.get("message"));
    }

    /**
     * Verifie qu'une connexion valide retourne un token.
     */
    @Test
    void shouldLoginSuccessfullyAndReturnToken() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword(passwordEncoder.encode("MotDePasse1@"));

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion reussie", response.get("message"));
        assertTrue(response.containsKey("token"));
    }

    /**
     * Verifie qu'un token valide autorise l'acces.
     */
    @Test
    void shouldAllowAccessWhenTokenIsValid() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("MotDePasse1@");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword(passwordEncoder.encode("MotDePasse1@"));

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> loginResponse = authService.login(request);
        String token = (String) loginResponse.get("token");

        Map<String, Object> protectedResponse = authService.accessProtectedData(token);

        assertEquals("Acces autorise", protectedResponse.get("message"));
        assertEquals("Donnees protegees fortes", protectedResponse.get("secret"));
    }

    /**
     * Verifie qu'un token invalide refuse l'acces.
     */
    @Test
    void shouldDenyAccessWhenTokenIsInvalid() {
        Map<String, Object> response = authService.accessProtectedData("token-invalide");

        assertEquals("Acces refuse", response.get("message"));
    }
}