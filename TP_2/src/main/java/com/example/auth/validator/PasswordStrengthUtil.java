package com.example.auth.validator;

/**
 * Utilitaire simple pour évaluer la force d'un mot de passe côté interface.
 *
 * Règles :
 * - rouge : mot de passe non conforme
 * - orange : mot de passe conforme mais encore moyen
 * - vert : mot de passe conforme et plus fort
 *
 * @author Poun
 * @version 2.5
 */
public class PasswordStrengthUtil {

    /**
     * Niveau rouge.
     */
    public static final String RED = "RED";

    /**
     * Niveau orange.
     */
    public static final String ORANGE = "ORANGE";

    /**
     * Niveau vert.
     */
    public static final String GREEN = "GREEN";

    /**
     * Vérifie si le mot de passe respecte la policy TP2.
     *
     * @param password mot de passe
     * @return true si valide, sinon false
     */
    public boolean isPolicyValid(String password) {
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
     * Vérifie si les deux mots de passe sont identiques.
     *
     * @param password mot de passe
     * @param confirmPassword confirmation
     * @return true si identiques
     */
    public boolean passwordsMatch(String password, String confirmPassword) {
        if (password == null || confirmPassword == null) {
            return false;
        }

        return password.equals(confirmPassword);
    }

    /**
     * Évalue le niveau de force du mot de passe.
     *
     * @param password mot de passe
     * @return RED, ORANGE ou GREEN
     */
    public String evaluate(String password) {
        if (!isPolicyValid(password)) {
            return RED;
        }

        if (password.length() >= 16) {
            return GREEN;
        }

        return ORANGE;
    }

    /**
     * Retourne le message à afficher.
     *
     * @param password mot de passe
     * @param confirmPassword confirmation
     * @return message utilisateur
     */
    public String getMessage(String password, String confirmPassword) {
        if (password == null || password.isBlank()) {
            return "Saisissez un mot de passe";
        }

        if (!isPolicyValid(password)) {
            return "Rouge : mot de passe non conforme";
        }

        if (!passwordsMatch(password, confirmPassword)) {
            return "Confirmation différente";
        }

        if (password.length() >= 16) {
            return "Vert : mot de passe conforme et bon niveau";
        }

        return "Orange : mot de passe conforme mais faible";
    }
}