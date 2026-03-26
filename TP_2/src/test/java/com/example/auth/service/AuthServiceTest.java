package com.example.auth.service;

import com.example.auth.AuthApplication;
import com.example.auth.dto.ClientProofRequest;
import com.example.auth.dto.ClientProofResponse;
import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Tests du service d'authentification TP3.
 *
 * Cas couverts :
 * - inscription
 * - login HMAC valide
 * - login HMAC invalide
 * - timestamp expiré
 * - timestamp futur
 * - nonce déjà utilisé
 * - utilisateur inconnu
 * - /me avec et sans token
 * - logout
 *
 * @author Poun
 * @version 3.4
 */
@SpringBootTest(classes = AuthApplication.class)
@ActiveProfiles("test")
public class AuthServiceTest {

    /**
     * Service principal.
     */
    @Autowired
    private AuthService authService;

    /**
     * Service de simulation client.
     */
    @Autowired
    private ClientProofService clientProofService;

    /**
     * Repository utilisateur.
     */
    @Autowired
    private UserRepository userRepository;

    /**
     * Repository nonce.
     */
    @Autowired
    private AuthNonceRepository authNonceRepository;

    /**
     * Nettoyage avant chaque test.
     */
    @BeforeEach
    void setUp() {
        authNonceRepository.deleteAll();
        userRepository.deleteAll();
    }

    /**
     * Crée un utilisateur de test.
     */
    private void registerDefaultUser() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");
        authService.register(request);
    }

    /**
     * Construit une preuve valide.
     *
     * @return preuve client valide
     */
    private ClientProofResponse buildValidProof() {
        ClientProofRequest request = new ClientProofRequest();
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");
        return clientProofService.buildProof(request);
    }

    /**
     * Transforme une preuve client en LoginRequest.
     *
     * @param proof preuve client
     * @return requête login
     */
    private LoginRequest toLoginRequest(ClientProofResponse proof) {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(proof.getEmail());
        loginRequest.setNonce(proof.getNonce());
        loginRequest.setTimestamp(proof.getTimestamp());
        loginRequest.setHmac(proof.getHmac());
        return loginRequest;
    }

    /**
     * Teste une inscription valide.
     */
    @Test
    void testRegisterSuccess() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Inscription réussie", response.get("message"));
        Assertions.assertTrue(userRepository.findByEmail("poun@gmail.com").isPresent());
    }

    /**
     * Teste une inscription avec email déjà utilisé.
     */
    @Test
    void testRegisterDuplicateEmail() {
        registerDefaultUser();

        RegisterRequest request = new RegisterRequest();
        request.setName("Autre");
        request.setEmail("poun@gmail.com");
        request.setPassword("Azerty1234!@");

        Map<String, Object> response = authService.register(request);

        Assertions.assertEquals("Email déjà utilisé", response.get("error"));
    }

    /**
     * Teste une inscription avec mot de passe faible.
     */
    @Test
    void testRegisterWeakPassword() {
        RegisterRequest request = new RegisterRequest();
        request.setName("Poun");
        request.setEmail("poun@gmail.com");
        request.setPassword("123");

        Map<String, Object> response = authService.register(request);

        Assertions.assertNotNull(response.get("error"));
    }

    /**
     * Teste le login avec HMAC valide.
     */
    @Test
    void testLoginOkWithValidHmac() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> response = authService.login(toLoginRequest(proof));

        Assertions.assertEquals("Connexion réussie", response.get("message"));
        Assertions.assertNotNull(response.get("accessToken"));
        Assertions.assertEquals("poun@gmail.com", response.get("email"));
        Assertions.assertNotNull(response.get("expiresAt"));
    }

    /**
     * Teste le login avec HMAC invalide.
     */
    @Test
    void testLoginKoInvalidHmac() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setHmac("hmac-faux");

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("HMAC invalide", response.get("error"));
    }

    /**
     * Teste le login avec timestamp expiré.
     */
    @Test
    void testLoginKoExpiredTimestamp() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setTimestamp((System.currentTimeMillis() / 1000) - 1000);

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Requête expirée", response.get("error"));
    }

    /**
     * Teste le login avec timestamp futur.
     */
    @Test
    void testLoginKoFutureTimestamp() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest loginRequest = toLoginRequest(proof);
        loginRequest.setTimestamp((System.currentTimeMillis() / 1000) + 1000);

        Map<String, Object> response = authService.login(loginRequest);

        Assertions.assertEquals("Requête expirée", response.get("error"));
    }

    /**
     * Teste le login avec nonce déjà utilisé.
     */
    @Test
    void testLoginKoNonceAlreadyUsed() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        LoginRequest firstLogin = toLoginRequest(proof);
        Map<String, Object> firstResponse = authService.login(firstLogin);

        Assertions.assertEquals("Connexion réussie", firstResponse.get("message"));

        LoginRequest secondLogin = toLoginRequest(proof);
        Map<String, Object> secondResponse = authService.login(secondLogin);

        Assertions.assertEquals("Nonce déjà utilisé", secondResponse.get("error"));
    }

    /**
     * Teste le login avec utilisateur inconnu.
     */
    @Test
    void testLoginKoUnknownUser() {
        ClientProofRequest request = new ClientProofRequest();
        request.setEmail("inconnu@gmail.com");
        request.setPassword("Azerty1234!@");

        ClientProofResponse proof = clientProofService.buildProof(request);

        Map<String, Object> response = authService.login(toLoginRequest(proof));

        Assertions.assertEquals("Utilisateur introuvable", response.get("error"));
    }

    /**
     * Teste le login sans email.
     */
    @Test
    void testLoginKoWithoutEmail() {
        LoginRequest request = new LoginRequest();
        request.setNonce("nonce-test");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        Assertions.assertEquals("Email obligatoire", response.get("error"));
    }

    /**
     * Teste le login sans nonce.
     */
    @Test
    void testLoginKoWithoutNonce() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setTimestamp(System.currentTimeMillis() / 1000);
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        Assertions.assertEquals("Nonce obligatoire", response.get("error"));
    }

    /**
     * Teste le login sans timestamp.
     */
    @Test
    void testLoginKoWithoutTimestamp() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setNonce("nonce-test");
        request.setHmac("abc");

        Map<String, Object> response = authService.login(request);

        Assertions.assertEquals("Timestamp obligatoire", response.get("error"));
    }

    /**
     * Teste le login sans HMAC.
     */
    @Test
    void testLoginKoWithoutHmac() {
        LoginRequest request = new LoginRequest();
        request.setEmail("poun@gmail.com");
        request.setNonce("nonce-test");
        request.setTimestamp(System.currentTimeMillis() / 1000);

        Map<String, Object> response = authService.login(request);

        Assertions.assertEquals("HMAC obligatoire", response.get("error"));
    }

    /**
     * Teste /me avec token valide.
     */
    @Test
    void testGetMeOkWithToken() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> loginResponse = authService.login(toLoginRequest(proof));
        String token = (String) loginResponse.get("accessToken");

        Map<String, Object> meResponse = authService.getMe("Bearer " + token);

        Assertions.assertEquals("Poun", meResponse.get("name"));
        Assertions.assertEquals("poun@gmail.com", meResponse.get("email"));
        Assertions.assertNotNull(meResponse.get("tokenExpiresAt"));
    }

    /**
     * Teste /me sans token.
     */
    @Test
    void testGetMeKoWithoutToken() {
        Map<String, Object> response = authService.getMe(null);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    /**
     * Teste /me avec token invalide.
     */
    @Test
    void testGetMeKoUnknownToken() {
        Map<String, Object> response = authService.getMe("Bearer token-inconnu");

        Assertions.assertEquals("Utilisateur non trouvé pour ce token", response.get("error"));
    }

    /**
     * Teste /me avec token expiré.
     */
    @Test
    void testGetMeKoExpiredToken() {
        registerDefaultUser();

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        user.setToken("token-expire");
        user.setTokenExpiresAt(LocalDateTime.now().minusMinutes(1));
        userRepository.save(user);

        Map<String, Object> response = authService.getMe("Bearer token-expire");

        Assertions.assertEquals("Token expiré ou invalide", response.get("error"));
    }

    /**
     * Teste logout avec token valide.
     */
    @Test
    void testLogoutOk() {
        registerDefaultUser();
        ClientProofResponse proof = buildValidProof();

        Map<String, Object> loginResponse = authService.login(toLoginRequest(proof));
        String token = (String) loginResponse.get("accessToken");

        Map<String, Object> logoutResponse = authService.logout("Bearer " + token);

        Assertions.assertEquals("Déconnexion réussie", logoutResponse.get("message"));

        User user = userRepository.findByEmail("poun@gmail.com").orElseThrow();
        Assertions.assertNull(user.getToken());
        Assertions.assertNull(user.getTokenExpiresAt());
    }

    /**
     * Teste logout sans token.
     */
    @Test
    void testLogoutKoWithoutToken() {
        Map<String, Object> response = authService.logout(null);

        Assertions.assertEquals("Token manquant ou invalide", response.get("error"));
    }

    /**
     * Teste logout avec token inconnu.
     */
    @Test
    void testLogoutKoUnknownToken() {
        Map<String, Object> response = authService.logout("Bearer token-inconnu");

        Assertions.assertEquals("Utilisateur non trouvé", response.get("error"));
    }
}