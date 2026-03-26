package com.example.auth.validator;

/**
 * Validateur simple de politique de mot de passe pour TP2.
 *
 * Règles imposées :
 * - au moins 12 caractères
 * - au moins une majuscule
 * - au moins une minuscule
 * - au moins un chiffre
 * - au moins un caractère spécial
 *
 * @author Poun
 * @version 2.2
 */
public class PasswordPolicyValidator {

    /**
     * Vérifie si le mot de passe respecte la politique demandée.
     *
     * @param password mot de passe à vérifier
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

        for (char c : password.toCharArray()) {
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

    /**
     * Retourne un message simple expliquant la règle.
     *
     * @return message de validation
     */
    public String getRulesMessage() {
        return "Le mot de passe doit contenir au moins 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.";
    }
}