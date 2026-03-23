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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

@SpringBootTest(classes = AuthApplication.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testRegisterSuccess() throws Exception {
        RegisterRequest r = new RegisterRequest();
        r.setName("Jean");
        r.setEmail("jean@gmail.com");
        r.setPassword("123");

        String res = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(r)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Inscription reussie"));
    }

    @Test
    void testRegisterDuplicate() throws Exception {
        RegisterRequest r = new RegisterRequest();
        r.setName("Sara");
        r.setEmail("sara@gmail.com");
        r.setPassword("123");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(r)));

        String res = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(r)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Email deja utilise"));
    }

    @Test
    void testRegisterWithoutEmail() throws Exception {
        RegisterRequest r = new RegisterRequest();
        r.setName("Test");
        r.setEmail("");
        r.setPassword("123");

        String res = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(r)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Email obligatoire"));
    }

    @Test
    void testLoginSuccess() throws Exception {
        RegisterRequest r = new RegisterRequest();
        r.setName("Marie");
        r.setEmail("marie@gmail.com");
        r.setPassword("123");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(r)));

        LoginRequest login = new LoginRequest();
        login.setEmail("marie@gmail.com");
        login.setPassword("123");

        String res = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Connexion reussie"));
    }

    @Test
    void testLoginWrongPassword() throws Exception {
        RegisterRequest r = new RegisterRequest();
        r.setName("Lucas");
        r.setEmail("lucas@gmail.com");
        r.setPassword("123");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(r)));

        LoginRequest login = new LoginRequest();
        login.setEmail("lucas@gmail.com");
        login.setPassword("999");

        String res = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Mot de passe incorrect"));
    }

    @Test
    void testLoginUserNotFound() throws Exception {
        LoginRequest login = new LoginRequest();
        login.setEmail("no@gmail.com");
        login.setPassword("123");

        String res = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(login)))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Utilisateur introuvable"));
    }

    @Test
    void testProtectedWithoutToken() throws Exception {
        String res = mockMvc.perform(get("/api/auth/protected"))
                .andReturn().getResponse().getContentAsString();

        Assertions.assertTrue(res.contains("Token manquant"));
    }
}