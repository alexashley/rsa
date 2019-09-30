package dev.alexashley.rsa

import java.math.BigInteger
import java.util.concurrent.ThreadLocalRandom

// https://en.wikipedia.org/wiki/Greatest_common_divisor#Euclid's_algorithm
fun gcd(a: BigInteger, b: BigInteger): BigInteger {
    if (b == BigInteger.ZERO) {
        return a
    }

    return gcd(b, a % b).abs()
}

// https://en.wikipedia.org/wiki/Least_common_multiple#Using_the_greatest_common_divisor
fun lcm(a: BigInteger, b: BigInteger): BigInteger {
    if (a == BigInteger.ZERO && b == BigInteger.ZERO) {
        return BigInteger.ZERO
    }

    return (a * b).abs() / gcd(a, b)
}

fun areCoprime(a: BigInteger, b: BigInteger): Boolean {
    return gcd(a, b) == BigInteger.ONE
}

fun randomBigInteger(min: BigInteger, max: BigInteger): BigInteger {
    val random = ThreadLocalRandom.current() // This should be SecureRandom, but it was painfully slow on Linux
    while (true) {
        val r = BigInteger(max.bitLength(), random)
        if (r in min..max) {
            return r
        }
    }
}

// https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Code
fun randomPrime(bits: Int): BigInteger {
    val min = BigInteger.valueOf(6074001000).shiftLeft(bits - 33)
    val max = BigInteger.ONE.shiftLeft(bits).minus(BigInteger.ONE)

    while (true) {
        val prime = randomBigInteger(min, max)

        if (prime.isProbablePrime(256)) {
            return prime
        }
    }
}

class Rsa(
        private val publicKeyPart1: BigInteger,
        private val publicKeyPart2: BigInteger,
        private val privateKey: BigInteger
) {
    companion object {
        fun generate(keySize: Int): Rsa {
            if (keySize % 2 != 0) {
                throw IllegalArgumentException("Key size must be even")
            }
            val primeBits = keySize / 2

            val e = BigInteger.valueOf(65537)

            while (true) {
                val p = randomPrime(primeBits)
                val q = randomPrime(primeBits)
                val lambda = lcm(p - BigInteger.ONE, q - BigInteger.ONE)

                if (areCoprime(e, lambda) || (p - q).abs().shiftRight(primeBits - 100) != BigInteger.ZERO) {
                    return Rsa(p * q, e, e.modInverse(lambda))
                }
            }

        }
    }

    fun encrypt(plaintext: BigInteger): BigInteger {
        return plaintext.modPow(publicKeyPart2, publicKeyPart1)
    }

    fun decrypt(cipherText: BigInteger): BigInteger {
        return cipherText.modPow(privateKey, publicKeyPart1)
    }
}
