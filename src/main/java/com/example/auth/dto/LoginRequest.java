package com.example.auth.dto;

/**
 * Classe utilisee pour transporter les donnees de connexion.
 * Elle contient l'email et le mot de passe saisis par l'utilisateur.
 */
public class LoginRequest {

    /**
     * Email de l'utilisateur.
     */
    private String email;

    /**
     * Mot de passe de l'utilisateur.
     */
    private String password;

    /**
     * Constructeur vide necessaire pour la deserialisation JSON.
     */
    public LoginRequest() {
    }

    /**
     * Retourne l'email.
     *
     * @return email de l'utilisateur
     */
    public String getEmail() {
        return email;
    }

    /**
     * Modifie l'email.
     *
     * @param email nouvel email
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Retourne le mot de passe.
     *
     * @return mot de passe
     */
    public String getPassword() {
        return password;
    }

    /**
     * Modifie le mot de passe.
     *
     * @param password nouveau mot de passe
     */
    public void setPassword(String password) {
        this.password = password;
    }
}