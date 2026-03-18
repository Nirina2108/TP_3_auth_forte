package com.example.auth.dto;

/**
 * Classe utilisee pour transporter les donnees d'inscription.
 * Elle contient les informations necessaires pour creer un utilisateur.
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
     * Mot de passe choisi par l'utilisateur.
     */
    private String password;

    /**
     * Constructeur vide necessaire pour la deserialisation JSON.
     */
    public RegisterRequest() {
    }

    /**
     * Retourne le nom.
     *
     * @return nom de l'utilisateur
     */
    public String getName() {
        return name;
    }

    /**
     * Modifie le nom.
     *
     * @param name nouveau nom
     */
    public void setName(String name) {
        this.name = name;
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