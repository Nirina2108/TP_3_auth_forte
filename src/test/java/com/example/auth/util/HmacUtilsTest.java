package com.example.auth.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Tests de HmacUtils.
 *
 * @author Poun
 * @version 1.0
 */
class HmacUtilsTest {

    /**
     * Vérifie qu'un HMAC est bien généré.
     */
    @Test
    void generateHmacShouldReturnValue() {
        String result = HmacUtils.generateHmac(
                "123456",
                "ikalo@gmail.com:nonce:123456"
        );

        Assertions.assertNotNull(result);
        Assertions.assertFalse(result.isBlank());
    }

    /**
     * Vérifie secureEquals sur deux chaînes identiques.
     */
    @Test
    void secureEqualsTrue() {
        Assertions.assertTrue(HmacUtils.secureEquals("abc", "abc"));
    }

    /**
     * Vérifie secureEquals sur deux chaînes différentes.
     */
    @Test
    void secureEqualsFalse() {
        Assertions.assertFalse(HmacUtils.secureEquals("abc", "xyz"));
    }

    /**
     * Vérifie secureEquals avec null.
     */
    @Test
    void secureEqualsWithNull() {
        Assertions.assertFalse(HmacUtils.secureEquals(null, "abc"));
    }
}