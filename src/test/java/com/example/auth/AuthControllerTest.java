package com.example.auth;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Tests du contrôleur d'authentification.
 *
 * @author Poun
 * @version 1.0
 */
@SpringBootTest(classes = AuthApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthControllerTest {

    /**
     * URL de base des routes d'authentification.
     */
    private static final String AUTH_URL = "/api/auth";

    /**
     * Texte attendu pour une inscription réussie.
     */
    private static final String MSG_REGISTER_OK = "Inscription reussie";

    /**
     * Texte attendu pour une connexion réussie.
     */
    private static final String MSG_LOGIN_OK = "Connexion reussie";

    /**
     * Texte attendu si email déjà utilisé.
     */
    private static final String MSG_EMAIL_USED = "Email deja utilise";

    /**
     * Texte attendu si email obligatoire.
     */
    private static final String MSG_EMAIL_REQUIRED = "Email obligatoire";

    /**
     * Texte attendu si mot de passe incorrect.
     */
    private static final String MSG_WRONG_PASSWORD = "Mot de passe incorrect";

    /**
     * Texte attendu si utilisateur introuvable.
     */
    private static final String MSG_USER_NOT_FOUND = "Utilisateur introuvable";

    /**
     * Texte attendu si token manquant.
     */
    private static final String MSG_TOKEN_MISSING = "Token manquant";

    /**
     * Outil pour convertir objet Java en JSON.
     */
    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Outil pour simuler les appels HTTP.
     */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Crée une requête d'inscription.
     *
     * @param name nom
     * @param email email
     * @param password mot de passe
     * @return objet RegisterRequest
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
     * @return objet LoginRequest
     */
    private LoginRequest buildLoginRequest(String email, String password) {
        LoginRequest request = new LoginRequest();
        request.setEmail(email);
        request.setPassword(password);
        return request;
    }

    /**
     * Envoie une requête POST /register et retourne la réponse texte.
     *
     * @param request données d'inscription
     * @return contenu texte de la réponse
     * @throws Exception si erreur
     */
    private String postRegister(RegisterRequest request) throws Exception {
        MvcResult result = mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(AUTH_URL + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
        ).andReturn();

        return result.getResponse().getContentAsString();
    }

    /**
     * Envoie une requête POST /login et retourne la réponse texte.
     *
     * @param request données de connexion
     * @return contenu texte de la réponse
     * @throws Exception si erreur
     */
    private String postLogin(LoginRequest request) throws Exception {
        MvcResult result = mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(AUTH_URL + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
        ).andReturn();

        return result.getResponse().getContentAsString();
    }

    /**
     * Vérifie qu'une inscription valide fonctionne.
     *
     * @throws Exception si erreur
     */
    @Test
    void testRegisterSuccess() throws Exception {
        RegisterRequest request = buildRegisterRequest("Jean", "jean@gmail.com", "123");
        String response = postRegister(request);

        Assertions.assertTrue(response.contains(MSG_REGISTER_OK));
    }

    /**
     * Vérifie qu'un email déjà utilisé est refusé.
     *
     * @throws Exception si erreur
     */
    @Test
    void testRegisterDuplicate() throws Exception {
        RegisterRequest request = buildRegisterRequest("Sara", "sara@gmail.com", "123");

        postRegister(request);
        String response = postRegister(request);

        Assertions.assertTrue(response.contains(MSG_EMAIL_USED));
    }

    /**
     * Vérifie qu'un email vide est refusé.
     *
     * @throws Exception si erreur
     */
    @Test
    void testRegisterWithoutEmail() throws Exception {
        RegisterRequest request = buildRegisterRequest("Test", "", "123");
        String response = postRegister(request);

        Assertions.assertTrue(response.contains(MSG_EMAIL_REQUIRED));
    }

    /**
     * Vérifie qu'une connexion valide fonctionne.
     *
     * @throws Exception si erreur
     */
    @Test
    void testLoginSuccess() throws Exception {
        RegisterRequest registerRequest = buildRegisterRequest("Marie", "marie@gmail.com", "123");
        postRegister(registerRequest);

        LoginRequest loginRequest = buildLoginRequest("marie@gmail.com", "123");
        String response = postLogin(loginRequest);

        Assertions.assertTrue(response.contains(MSG_LOGIN_OK));
    }

    /**
     * Vérifie qu'un mauvais mot de passe est refusé.
     *
     * @throws Exception si erreur
     */
    @Test
    void testLoginWrongPassword() throws Exception {
        RegisterRequest registerRequest = buildRegisterRequest("Lucas", "lucas@gmail.com", "123");
        postRegister(registerRequest);

        LoginRequest loginRequest = buildLoginRequest("lucas@gmail.com", "999");
        String response = postLogin(loginRequest);

        Assertions.assertTrue(response.contains(MSG_WRONG_PASSWORD));
    }

    /**
     * Vérifie qu'un utilisateur absent est refusé.
     *
     * @throws Exception si erreur
     */
    @Test
    void testLoginUserNotFound() throws Exception {
        LoginRequest loginRequest = buildLoginRequest("no@gmail.com", "123");
        String response = postLogin(loginRequest);

        Assertions.assertTrue(response.contains(MSG_USER_NOT_FOUND));
    }

    /**
     * Vérifie qu'un accès protégé sans token est refusé.
     *
     * @throws Exception si erreur
     */
    @Test
    void testProtectedWithoutToken() throws Exception {
        MvcResult result = mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(AUTH_URL + "/protected")
        ).andReturn();

        String response = result.getResponse().getContentAsString();

        Assertions.assertTrue(response.contains(MSG_TOKEN_MISSING));
    }
}