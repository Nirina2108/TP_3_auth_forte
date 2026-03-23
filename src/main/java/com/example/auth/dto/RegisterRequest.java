package com.example.auth.dto;

/**
 * Objet utilisé pour recevoir les données d'inscription.
 *
 * @author Poun
 * @version 1.0
 */
public class RegisterRequest {

    /**
     * Nom de l'utilisateur.
     */
    private String name;

    /**
     * Email de l'utilisateur.
     */
    private String email;

    /**
     * Mot de passe de l'utilisateur.
     */
    private String password;

    /**
     * Constructeur vide.
     */
    public RegisterRequest() {
    }

    /**
     * Retourne le nom.
     *
     * @return nom
     */
    public String getName() {
        return name;
    }

    /**
     * Définit le nom.
     *
     * @param name nom utilisateur
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Retourne l'email.
     *
     * @return email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Définit l'email.
     *
     * @param email email utilisateur
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
     * Définit le mot de passe.
     *
     * @param password mot de passe utilisateur
     */
    public void setPassword(String password) {
        this.password = password;
    }
}