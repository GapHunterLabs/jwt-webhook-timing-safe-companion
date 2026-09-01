package dev.gaphunter.jwtwebhooktimingsafecompanion.detect

/**
 * Text signals this plugin uses to decide "this method actually
 * computes an HMAC" and "this identifier plausibly refers to a
 * signature". Deliberately broad substring matches over method body
 * text and identifier names (not resolved types) -- same "match a
 * known name, don't resolve a symbol" discipline as
 * `SignatureVerificationSignals` in `webhook-signature-companion`.
 */
object HmacComparisonSignals {

    private val HMAC_COMPUTATION_FRAGMENTS = listOf("mac.getinstance", "hmacsha", "\"hmac", "hmac_sha")

    private val SIGNATURE_NAME_FRAGMENTS = listOf("sig", "hmac", "hash", "digest", "mac")

    private const val SAFE_COMPARISON_FRAGMENT = "messagedigest.isequal"

    /** True when [bodyText] contains real evidence of computing an HMAC (not just checking one exists elsewhere). */
    fun computesHmac(bodyText: String): Boolean {
        val lower = bodyText.lowercase()
        return HMAC_COMPUTATION_FRAGMENTS.any { lower.contains(it) }
    }

    /** True when [bodyText] anywhere already uses the constant-time comparison -- the method is assumed already safe. */
    fun alreadyUsesConstantTimeComparison(bodyText: String): Boolean =
        bodyText.lowercase().contains(SAFE_COMPARISON_FRAGMENT)

    /** True when [identifierText] plausibly names a signature/digest value, e.g. `computedSignature`, `expectedHmac`, `sigHeader`. */
    fun looksLikeSignatureIdentifier(identifierText: String): Boolean {
        val lower = identifierText.lowercase()
        return SIGNATURE_NAME_FRAGMENTS.any { lower.contains(it) }
    }
}
