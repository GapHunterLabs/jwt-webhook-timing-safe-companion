package dev.gaphunter.jwtwebhooktimingsafecompanion.model

import com.intellij.psi.PsiElement

enum class ComparisonKind {
    /** `x.equals(y)` -- e.g. `computedSignature.equals(receivedSignature)`. */
    DOT_EQUALS,

    /** `Arrays.equals(x, y)`. */
    ARRAYS_EQUALS,
}

/** One comparison site inside an HMAC-computing method that uses a non-constant-time comparison instead of `MessageDigest.isEqual`. */
data class UnsafeComparisonHit(
    val anchor: PsiElement,
    val kind: ComparisonKind,
)
