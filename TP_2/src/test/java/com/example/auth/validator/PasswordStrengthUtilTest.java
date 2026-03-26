package com.example.auth.validator;

/**
 * Utilitaire simple pour évaluer la force d'un mot de passe côté interface.
 *
 * @author Poun
 * @version 2.5
 */
public class PasswordStrengthUtilTest{

    public static final String RED = "RED";
    public static final String ORANGE = "ORANGE";
    public static final String GREEN = "GREEN";

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

    public boolean passwordsMatch(String password, String confirmPassword) {
        if (password == null || confirmPassword == null) {
            return false;
        }

        return password.equals(confirmPassword);
    }

    public String evaluate(String password) {
        if (!isPolicyValid(password)) {
            return RED;
        }

        if (password.length() >= 16) {
            return GREEN;
        }

        return ORANGE;
    }

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