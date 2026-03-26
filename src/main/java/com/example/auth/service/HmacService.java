package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service utilitaire pour le HMAC SHA-256.
 *
 * Version TP3 correcte :
 * - clé = mot de passe utilisateur
 * - message = email:nonce:timestamp
 *
 * @author Poun
 * @version 3.6
 */
@Service
public class HmacService {

    /**
     * Construit le message à signer.
     *
     * @param email email
     * @param nonce nonce
     * @param timestamp timestamp
     * @return message formaté
     */
    public String buildMessage(String email, String nonce, long timestamp) {
        return email.trim() + ":" + nonce.trim() + ":" + timestamp;
    }

    /**
     * Génère le HMAC SHA-256 avec une clé dynamique (mot de passe).
     *
     * @param key mot de passe utilisateur
     * @param message message à signer
     * @return HMAC Base64
     */
    public String hmacSha256(String key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKey =
                    new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");

            mac.init(secretKey);

            byte[] rawHmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(rawHmac);

        } catch (Exception e) {
            throw new RuntimeException("Erreur HMAC", e);
        }
    }
}