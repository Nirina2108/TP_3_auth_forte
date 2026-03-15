package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    /*
     * Pour le TP2, on commence a utiliser passwordHash.
     * Mais on garde temporairement les autres champs utilises
     * par le projet pour ne pas casser la compilation.
     */
    @Column(name = "password_hash")
    private String passwordHash;

    private String token;

    private LocalDateTime createdAt;

    public User() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    /*
     * Methode temporaire pour eviter de casser AuthService.
     * Pour l'instant, getPassword retourne passwordHash.
     */
    public String getPassword() {
        return passwordHash;
    }

    /*
     * Methode temporaire pour eviter de casser AuthService.
     * Pour l'instant, setPassword enregistre dans passwordHash.
     */
    public void setPassword(String password) {
        this.passwordHash = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
    private int failedAttempts;

    private LocalDateTime lockUntil;

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public LocalDateTime getLockUntil() {
        return lockUntil;
    }

    public void setLockUntil(LocalDateTime lockUntil) {
        this.lockUntil = lockUntil;
    }
}

