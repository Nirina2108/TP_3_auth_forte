package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Classe de test de AuthService.
 * Elle verifie le bon fonctionnement des methodes
 * d'inscription, de connexion et de recuperation
 * de l'utilisateur via le token.
 */
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    /**
     * Faux repository utilise pour simuler les acces a la base.
     */
    @Mock
    private UserRepository userRepository;

    /**
     * Service teste avec injection automatique du mock.
     */
    @InjectMocks
    private AuthService authService;

    /**
     * Outil utilise dans les tests pour generer un hash de mot de passe.
     */
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * Verifie qu'une inscription valide fonctionne correctement.
     */
    @Test
    public void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User savedUser = new User();
        savedUser.setName("Paul");
        savedUser.setEmail("paul@mail.com");

        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        User result = authService.register(request);

        assertNotNull(result);
        assertEquals("Paul", result.getName());
        assertEquals("paul@mail.com", result.getEmail());
        verify(userRepository, times(1)).save(any(User.class));
    }

    /**
     * Verifie que l'inscription echoue si le nom est null.
     */
    @Test
    public void testRegisterNameNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName(null);
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Name obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si le nom est vide.
     */
    @Test
    public void testRegisterNameBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("   ");
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Name obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si l'email est null.
     */
    @Test
    public void testRegisterEmailNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail(null);
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Email obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si l'email est vide.
     */
    @Test
    public void testRegisterEmailBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("   ");
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Email obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe est null.
     */
    @Test
    public void testRegisterPasswordNull() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Password obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe est vide.
     */
    @Test
    public void testRegisterPasswordBlank() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("   ");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals("Password obligatoire", exception.getMessage());
    }

    /**
     * Verifie que l'inscription echoue si le mot de passe
     * ne respecte pas la politique de securite.
     */
    @Test
    public void testRegisterPasswordInvalid() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Paul");
        request.setEmail("paul@mail.com");
        request.setPassword("abc");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.register(request));
        assertEquals(
                "Password invalide : minimum 12 caracteres, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractere special",
                exception.getMessage()
        );
    }

    /**
     * Verifie qu'une connexion valide retourne bien un token.
     */
    @Test
    public void testLoginSuccess() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        String token = authService.login(request);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(0, user.getFailedAttempts());
        assertNull(user.getLockUntil());
        assertNotNull(user.getToken());
        verify(userRepository, times(1)).save(user);
    }

    /**
     * Verifie que la connexion echoue si l'email est null.
     */
    @Test
    public void testLoginEmailNull() {
        LoginRequest request = new LoginRequest();
        request.setEmail(null);
        request.setPassword("Password123!");

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Email obligatoire", exception.getMessage());
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est null.
     */
    @Test
    public void testLoginPasswordNull() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword(null);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Mot de passe obligatoire", exception.getMessage());
    }

    /**
     * Verifie que la connexion echoue si l'utilisateur n'existe pas.
     */
    @Test
    public void testLoginUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Utilisateur introuvable", exception.getMessage());
    }

    /**
     * Verifie que la connexion echoue si le mot de passe est faux
     * et que le nombre d'essais est incremente.
     */
    @Test
    public void testLoginWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("WrongPassword123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Identifiants invalides", exception.getMessage());
        assertEquals(1, user.getFailedAttempts());
        verify(userRepository, times(1)).save(user);
    }

    /**
     * Verifie que la connexion echoue si le compte est temporairement bloque.
     */
    @Test
    public void testLoginBlockedAccount() {
        LoginRequest request = new LoginRequest();
        request.setEmail("paul@mail.com");
        request.setPassword("Password123!");

        User user = new User();
        user.setEmail("paul@mail.com");
        user.setPasswordHash(passwordEncoder.encode("Password123!"));
        user.setFailedAttempts(5);
        user.setLockUntil(LocalDateTime.now().plusMinutes(1));

        when(userRepository.findByEmail("paul@mail.com")).thenReturn(Optional.of(user));

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.login(request));
        assertEquals("Compte bloque temporairement. Reessayez plus tard", exception.getMessage());
    }

    /**
     * Verifie que la recuperation de l'utilisateur fonctionne avec un token valide.
     */
    @Test
    public void testGetMeSuccess() {
        User user = new User();
        user.setName("Paul");
        user.setEmail("paul@mail.com");
        user.setToken("abc123");

        when(userRepository.findByToken("abc123")).thenReturn(Optional.of(user));

        User result = authService.getMe("abc123");

        assertNotNull(result);
        assertEquals("Paul", result.getName());
        assertEquals("paul@mail.com", result.getEmail());
    }

    /**
     * Verifie que la recuperation de l'utilisateur echoue
     * si le token est invalide.
     */
    @Test
    public void testGetMeTokenInvalid() {
        when(userRepository.findByToken("bad-token")).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> authService.getMe("bad-token"));
        assertEquals("Token invalide", exception.getMessage());
    }
}