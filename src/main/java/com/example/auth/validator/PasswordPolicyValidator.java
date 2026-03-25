package com.example.auth.validator;

/**
 * Classe chargee de verifier si un mot de passe respecte
 * la politique minimale de securite.
 *
 * Regles :
 * - 12 caracteres minimum
 * - au moins une majuscule
 * - au moins une minuscule
 * - au moins un chiffre
 * - au moins un caractere special
 */
public class PasswordPolicyValidator {

    /**
     * Verifie si un mot de passe est valide.
     *
     * @param password mot de passe a verifier
     * @return true si le mot de passe est valide, sinon false
     */
    public boolean isValid(String password) {
        if (password == null) {
            return false;
        }

        if (password.length() < 12) {
            return false;
        }

        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);

            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowercase = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else {
                hasSpecial = true;
            }
        }

        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }
}