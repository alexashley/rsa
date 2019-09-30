package dev.alexashley.rsa

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RsaTest {
    private fun big(i: Long): BigInteger = BigInteger.valueOf(i)

    @Test
    fun `test gcd`() {
        assertEquals(big(6), gcd(big(48), big(18)))
        assertEquals(big(14), gcd(big(42), big(56)))
        assertEquals(big(1), gcd(big(3), big(5)))
        assertEquals(big(1), gcd(big(-3), big(5)))
        assertEquals(BigInteger.ZERO, gcd(BigInteger.ZERO, BigInteger.ZERO))
    }

    @Test
    fun `test lcm`() {
        assertEquals(big(12), lcm(big(4), big(6)))
        assertEquals(big(35), lcm(big(7), big(5)))
        assertEquals(BigInteger.ZERO, lcm(BigInteger.ZERO, BigInteger.ZERO))
        assertEquals(BigInteger.ZERO, lcm(big(5), BigInteger.ZERO))
    }

    @Test
    fun `test areCoprime`() {
        assertTrue(areCoprime(big(3), big(5)))
        assertTrue(areCoprime(big(19), big(42)))
        assertFalse(areCoprime(big(2), big(4)))
        assertFalse(areCoprime(big(10), big(400)))
    }

    @Test
    fun `test randomBigInteger`() {
        val a = randomBigInteger(big(1), big(5))

        assertTrue(a >= big(1))
        assertTrue(a <= big(5))
    }

    @Test
    fun `test randomPrime`() {
        assertTrue(randomPrime(128).isProbablePrime(256))
    }

    @Test
    fun `test rsa complete`() {
        val keyPair = Rsa.generate(128)
        val plaintext = BigInteger.valueOf(1234)
        val encrypted = keyPair.encrypt(plaintext)
        val decrypted = keyPair.decrypt(encrypted)

        assertEquals(plaintext, decrypted)
    }
}
