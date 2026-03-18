package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entite representant un utilisateur dans la base de donnees.
 * Elle contient les informations d'identite, d'authentification
 * et de securite (tentatives de connexion, blocage, token).
 */
@Entity
@Table(name = "users")
public class User {

    /**
     * Identifiant unique de l'utilisateur.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Nom de l'utilisateur.
     */
    private String name;

    /**
     * Email de l'utilisateur.
     */
    private String email;

    /**
     * Mot de passe chiffre de l'utilisateur.
     */
    @Column(name = "password_hash")
    private String passwordHash;

    /**
     * Token de session de l'utilisateur.
     */
    private String token;

    /**
     * Date de creation du compte.
     */
    private LocalDateTime createdAt;

    /**
     * Nombre de tentatives de connexion echouees.
     */
    private int failedAttempts;

    /**
     * Date jusqu'a laquelle le compte est bloque.
     */
    private LocalDateTime lockUntil;

    /**
     * Constructeur vide necessaire pour JPA.
     */
    public User() {
    }

    /**
     * Retourne l'identifiant.
     *
     * @return id utilisateur
     */
    public Long getId() {
        return id;
    }

    /**
     * Modifie l'identifiant.
     *
     * @param id nouvel id
     */
    public void setId(Long id) {
        this.id = id;
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
     * @return email utilisateur
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
     * Retourne le mot de passe chiffre.
     *
     * @return mot de passe chiffre
     */
    public String getPasswordHash() {
        return passwordHash;
    }

    /**
     * Modifie le mot de passe chiffre.
     *
     * @param passwordHash mot de passe chiffre
     */
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    /**
     * Methode temporaire pour compatibilite.
     * Retourne le mot de passe chiffre.
     *
     * @return mot de passe chiffre
     */
    public String getPassword() {
        return passwordHash;
    }

    /**
     * Methode temporaire pour compatibilite.
     * Enregistre le mot de passe dans passwordHash.
     *
     * @param password mot de passe
     */
    public void setPassword(String password) {
        this.passwordHash = password;
    }

    /**
     * Retourne le token.
     *
     * @return token utilisateur
     */
    public String getToken() {
        return token;
    }

    /**
     * Modifie le token.
     *
     * @param token nouveau token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Retourne la date de creation.
     *
     * @return date de creation
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Modifie la date de creation.
     *
     * @param createdAt nouvelle date
     */
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Retourne le nombre de tentatives echouees.
     *
     * @return nombre de tentatives
     */
    public int getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Modifie le nombre de tentatives echouees.
     *
     * @param failedAttempts nouveau nombre
     */
    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Retourne la date de blocage.
     *
     * @return date de blocage
     */
    public LocalDateTime getLockUntil() {
        return lockUntil;
    }

    /**
     * Modifie la date de blocage.
     *
     * @param lockUntil nouvelle date
     */
    public void setLockUntil(LocalDateTime lockUntil) {
        this.lockUntil = lockUntil;
    }
}