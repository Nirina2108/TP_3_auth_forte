package com.example.auth.validator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordPolicyValidatorTest {

    private final PasswordPolicyValidator validator = new PasswordPolicyValidator();

    @Test
    void shouldReturnFalseWhenPasswordIsNull() {
        assertFalse(validator.isValid(null));
    }

    @Test
    void shouldReturnFalseWhenPasswordIsTooShort() {
        assertFalse(validator.isValid("Abc123!"));
    }

    @Test
    void shouldReturnFalseWhenPasswordHasNoUppercase() {
        assertFalse(validator.isValid("motdepasse123!"));
    }

    @Test
    void shouldReturnFalseWhenPasswordHasNoLowercase() {
        assertFalse(validator.isValid("MOTDEPASSE123!"));
    }

    @Test
    void shouldReturnFalseWhenPasswordHasNoDigit() {
        assertFalse(validator.isValid("Motdepasse!!!"));
    }

    @Test
    void shouldReturnFalseWhenPasswordHasNoSpecialChar() {
        assertFalse(validator.isValid("Motdepasse123"));
    }

    @Test
    void shouldReturnTrueWhenPasswordIsValid() {
        assertTrue(validator.isValid("Motdepasse123!"));
    }

    @Test
    void shouldReturnTrueWhenPasswordIsValidAndLong() {
        assertTrue(validator.isValid("MonSuperMotdepasse123!"));
    }
}