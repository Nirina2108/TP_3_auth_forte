package com.example.auth.validator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests de la classe PasswordPolicyValidator.
 *
 * @author Poun
 * @version 1.0
 */
class PasswordPolicyValidatorTest {

    /**
     * Validateur a tester.
     */
    private final PasswordPolicyValidator validator = new PasswordPolicyValidator();

    /**
     * Verifie qu'un mot de passe null est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordIsNull() {
        assertFalse(validator.isValid(null));
    }

    /**
     * Verifie qu'un mot de passe trop court est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordIsTooShort() {
        assertFalse(validator.isValid("Abc1@short"));
    }

    /**
     * Verifie qu'un mot de passe sans majuscule est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordHasNoUppercase() {
        assertFalse(validator.isValid("motdepasse1@aa"));
    }

    /**
     * Verifie qu'un mot de passe sans minuscule est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordHasNoLowercase() {
        assertFalse(validator.isValid("MOTDEPASSE1@A"));
    }

    /**
     * Verifie qu'un mot de passe sans chiffre est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordHasNoDigit() {
        assertFalse(validator.isValid("MotDePasse@@@"));
    }

    /**
     * Verifie qu'un mot de passe sans caractere special est invalide.
     */
    @Test
    void shouldReturnFalseWhenPasswordHasNoSpecialCharacter() {
        assertFalse(validator.isValid("MotDePasse123"));
    }

    /**
     * Verifie qu'un mot de passe complet est valide.
     */
    @Test
    void shouldReturnTrueWhenPasswordIsStrong() {
        assertTrue(validator.isValid("MotDePasse1@"));
    }
}