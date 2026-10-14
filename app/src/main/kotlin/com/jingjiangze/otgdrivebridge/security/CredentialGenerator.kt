package com.jingjiangze.otgdrivebridge.security

import kotlin.math.ln

/**
 * Generates high-entropy credentials for the WebDAV account.
 *
 * The password is produced by [SecureRandom] over an alphabet that is safe to
 * paste into a Windows credential prompt (no shell-special characters) and is
 * displayed in full so the user can type it once. It is never logged.
 */
object CredentialGenerator {

    /**
     * No quote/backslash/space characters: safe to type into a Windows prompt.
     *
     * `internal` rather than `private` so tests can assert that every generated
     * character comes from this set.
     */
    internal const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

    const val DEFAULT_USERNAME = "otg"
    const val DEFAULT_PASSWORD_LENGTH = 24

    private val random = java.security.SecureRandom()

    fun username(): String = DEFAULT_USERNAME

    /**
     * Returns a password of [length] characters drawn from [ALPHABET].
     * Entropy is ~5.74 bits per character (57 symbols), so 24 chars ≈ 138 bits.
     */
    fun password(length: Int = DEFAULT_PASSWORD_LENGTH): String {
        require(length >= MIN_LENGTH) { "password length must be >= $MIN_LENGTH" }
        return buildString(length) {
            repeat(length) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
        }
    }

    /** Shannon entropy in bits of a password of [length] over [ALPHABET]. */
    fun entropyBits(length: Int = DEFAULT_PASSWORD_LENGTH): Double =
        length * ln(ALPHABET.length.toDouble()) / ln(2.0)

    const val MIN_LENGTH = 16
}
