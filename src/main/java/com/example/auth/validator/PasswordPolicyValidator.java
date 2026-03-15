package com.example.auth.validator;

/**
 * Verifie si un mot de passe respecte la politique demandee au TP2.
 *
 * Regles :
 * - 12 caracteres minimum
 * - 1 majuscule
 * - 1 minuscule
 * - 1 chiffre
 * - 1 caractere special
 */
public class PasswordPolicyValidator {

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