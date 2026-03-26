package com.example.auth.validator;

/**
 * Utilitaire pour évaluer la force d'un mot de passe.
 */
public class PasswordStrengthUtil {

    /**
     * Calcule un score simple de robustesse.
     *
     * @param password mot de passe
     * @return score
     */
    public static int calculateStrength(String password) {

        if (password == null) return 0;

        int score = 0;

        if (password.length() >= 8) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[!@#$%^&*()].*")) score++;

        return score;
    }
}