package com.example.auth.dto;

/**
 * DTO pour la connexion TP3.
 *
 * En TP3, le mot de passe n'est plus envoyé dans la requête de login.
 * Le client envoie une preuve signée composée de :
 * - email
 * - nonce
 * - timestamp
 * - hmac
 *
 * @author Poun
 * @version 3.2
 */
public class LoginRequest {

    /**
     * Email de l'utilisateur.
     */
    private String email;

    /**
     * Nonce aléatoire unique pour limiter le rejeu.
     */
    private String nonce;

    /**
     * Timestamp epoch en secondes.
     */
    private long timestamp;

    /**
     * Signature HMAC SHA-256.
     */
    private String hmac;

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
     * Retourne le nonce.
     *
     * @return nonce
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Modifie le nonce.
     *
     * @param nonce nouveau nonce
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Retourne le timestamp.
     *
     * @return timestamp epoch secondes
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Modifie le timestamp.
     *
     * @param timestamp nouveau timestamp
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Retourne le HMAC.
     *
     * @return signature hmac
     */
    public String getHmac() {
        return hmac;
    }

    /**
     * Modifie le HMAC.
     *
     * @param hmac nouvelle signature
     */
    public void setHmac(String hmac) {
        this.hmac = hmac;
    }
}