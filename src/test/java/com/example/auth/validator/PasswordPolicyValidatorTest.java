package com.example.auth.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests de la classe PasswordPolicyValidator.
 */
class PasswordPolicyValidatorTest {

    @Test
    void passwordValide() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertTrue(validator.isValid("Password123!"));
    }

    @Test
    void passwordTropCourt() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("Pass1!"));
    }

    @Test
    void passwordSansMajuscule() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("password123!"));
    }

    @Test
    void passwordSansMinuscule() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("PASSWORD123!"));
    }

    @Test
    void passwordSansChiffre() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("PasswordTest!"));
    }

    @Test
    void passwordSansCaractereSpecial() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid("Password1234"));
    }

    @Test
    void passwordNull() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid(null));
    }

    @Test
    void passwordVide() {
        PasswordPolicyValidator validator = new PasswordPolicyValidator();
        Assertions.assertFalse(validator.isValid(""));
    }
}