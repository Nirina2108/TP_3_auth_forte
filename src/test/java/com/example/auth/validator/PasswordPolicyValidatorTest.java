package com.example.auth.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests de la classe PasswordPolicyValidator.
 *
 * @author Poun
 * @version 1.0
 */
class PasswordPolicyValidatorTest {

    /**
     * Verifie qu'un mot de passe valide est accepte.
     */
    @Test
    void passwordValide() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertTrue(validator.isValid("Password123!"));
    }

    /**
     * Verifie qu'un mot de passe trop court est refuse.
     */
    @Test
    void passwordTropCourt() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("Pass1!"));
    }

    /**
     * Verifie qu'un mot de passe sans majuscule est refuse.
     */
    @Test
    void passwordSansMajuscule() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("password123!"));
    }

    /**
     * Verifie qu'un mot de passe sans minuscule est refuse.
     */
    @Test
    void passwordSansMinuscule() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("PASSWORD123!"));
    }

    /**
     * Verifie qu'un mot de passe sans chiffre est refuse.
     */
    @Test
    void passwordSansChiffre() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("PasswordTest!"));
    }

    /**
     * Verifie qu'un mot de passe sans caractere special est refuse.
     */
    @Test
    void passwordSansCaractereSpecial() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("Password1234"));
    }

    /**
     * Verifie qu'un mot de passe null est refuse.
     */
    @Test
    void passwordNull() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid(null));
    }

    /**
     * Verifie qu'un mot de passe vide est refuse.
     */
    @Test
    void passwordVide() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid(""));
    }
}