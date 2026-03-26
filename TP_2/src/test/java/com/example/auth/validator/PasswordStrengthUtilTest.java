package com.example.auth.validator;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests pour vérifier la robustesse du mot de passe.
 */
public class PasswordStrengthUtilTest {

    @Test
    void testWeakPassword() {
        String password = "123";
        int score = PasswordStrengthUtil.calculateStrength(password);
        Assertions.assertTrue(score < 3);
    }

    @Test
    void testMediumPassword() {
        String password = "Azerty123";
        int score = PasswordStrengthUtil.calculateStrength(password);
        Assertions.assertTrue(score >= 3);
    }

    @Test
    void testStrongPassword() {
        String password = "Azerty123!@#";
        int score = PasswordStrengthUtil.calculateStrength(password);
        Assertions.assertTrue(score >= 4);
    }
}