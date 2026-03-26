package com.example.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur.
 *
 * TP2 étape 4 :
 * - mot de passe stocké en password_hash
 * - token simple
 * - protection anti brute force
 *
 * @author Poun
 * @version 2.4
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
    @Column(nullable = false)
    private String name;

    /**
     * Email unique de l'utilisateur.
     */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * Mot de passe hashé avec BCrypt.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /**
     * Token simple d'authentification.
     */
    @Column(length = 255)
    private String token;

    /**
     * Date de création du compte.
     */
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /**
     * Nombre d'échecs de connexion.
     */
    @Column(name = "failed_attempts")
    private int failedAttempts;

    /**
     * Date/heure de fin de blocage.
     */
    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    /**
     * Constructeur vide.
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
     * @param id nouvel identifiant
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Retourne le nom.
     *
     * @return nom utilisateur
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
     * Retourne le mot de passe hashé.
     *
     * @return mot de passe hashé
     */
    public String getPasswordHash() {
        return passwordHash;
    }

    /**
     * Modifie le mot de passe hashé.
     *
     * @param passwordHash nouveau hash
     */
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
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
     * Retourne la date de création.
     *
     * @return date de création
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Modifie la date de création.
     *
     * @param createdAt nouvelle date
     */
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Retourne le nombre d'échecs.
     *
     * @return nombre d'échecs
     */
    public int getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Modifie le nombre d'échecs.
     *
     * @param failedAttempts nouveau nombre d'échecs
     */
    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Retourne la date de fin de blocage.
     *
     * @return date de fin de blocage
     */
    public LocalDateTime getLockUntil() {
        return lockUntil;
    }

    /**
     * Modifie la date de fin de blocage.
     *
     * @param lockUntil nouvelle date de blocage
     */
    public void setLockUntil(LocalDateTime lockUntil) {
        this.lockUntil = lockUntil;
    }
}