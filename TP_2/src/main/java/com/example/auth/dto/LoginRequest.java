package com.example.auth.dto;

/**
 * DTO pour la connexion utilisateur.
 *
 * @author Poun
 * @version 1.0
 */
public class LoginRequest {

    private String email;
    private String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}