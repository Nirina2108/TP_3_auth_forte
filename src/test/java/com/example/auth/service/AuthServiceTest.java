package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private UserRepository userRepository;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        authService = new AuthService(userRepository);
    }

    @Test
    void register_shouldReturnNomObligatoire_whenNameIsEmpty() {
        RegisterRequest request = new RegisterRequest();
        request.setName("");
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        Map<String, Object> response = authService.register(request);

        assertEquals("Nom obligatoire", response.get("message"));
    }

    @Test
    void register_shouldReturnEmailObligatoire_whenEmailIsEmpty() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("");
        request.setPassword("1234");

        Map<String, Object> response = authService.register(request);

        assertEquals("Email obligatoire", response.get("message"));
    }

    @Test
    void register_shouldReturnPasswordObligatoire_whenPasswordIsEmpty() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("");

        Map<String, Object> response = authService.register(request);

        assertEquals("Mot de passe obligatoire", response.get("message"));
    }

    @Test
    void register_shouldReturnEmailDejaUtilise_whenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        User existingUser = new User();
        existingUser.setEmail("test@mail.com");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(existingUser));

        Map<String, Object> response = authService.register(request);

        assertEquals("Email deja utilise", response.get("message"));
    }

    @Test
    void register_shouldReturnInscriptionReussie_whenRequestIsValid() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.register(request);

        assertEquals("Inscription reussie", response.get("message"));
        assertNotNull(response.get("user"));
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void login_shouldReturnEmailObligatoire_whenEmailIsEmpty() {
        LoginRequest request = new LoginRequest();
        request.setEmail("");
        request.setPassword("1234");

        Map<String, Object> response = authService.login(request);

        assertEquals("Email obligatoire", response.get("message"));
    }

    @Test
    void login_shouldReturnPasswordObligatoire_whenPasswordIsEmpty() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("");

        Map<String, Object> response = authService.login(request);

        assertEquals("Mot de passe obligatoire", response.get("message"));
    }

    @Test
    void login_shouldReturnUtilisateurIntrouvable_whenUserDoesNotExist() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.empty());

        Map<String, Object> response = authService.login(request);

        assertEquals("Utilisateur introuvable", response.get("message"));
    }

    @Test
    void login_shouldReturnMotDePasseIncorrect_whenPasswordIsWrong() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("mauvais");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword("bonmotdepasse");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Mot de passe incorrect", response.get("message"));
    }

    @Test
    void login_shouldReturnConnexionReussieAndToken_whenCredentialsAreValid() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword("1234");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> response = authService.login(request);

        assertEquals("Connexion reussie", response.get("message"));
        assertNotNull(response.get("token"));
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenTokenDoesNotExist() {
        assertFalse(authService.isTokenValid("token-invalide"));
    }

    @Test
    void isTokenValid_shouldReturnTrue_whenTokenExists() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword("1234");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> loginResponse = authService.login(request);
        String token = (String) loginResponse.get("token");

        assertTrue(authService.isTokenValid(token));
    }

    @Test
    void accessProtectedData_shouldReturnAccesRefuse_whenTokenIsInvalid() {
        Map<String, Object> response = authService.accessProtectedData("faux-token");

        assertEquals("Acces refuse", response.get("message"));
    }

    @Test
    void accessProtectedData_shouldReturnAccesAutorise_whenTokenIsValid() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@mail.com");
        request.setPassword("1234");

        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setPassword("1234");

        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(user));

        Map<String, Object> loginResponse = authService.login(request);
        String token = (String) loginResponse.get("token");

        Map<String, Object> response = authService.accessProtectedData(token);

        assertEquals("Acces autorise", response.get("message"));
        assertEquals("Donnees protegees fragiles", response.get("secret"));
    }
}