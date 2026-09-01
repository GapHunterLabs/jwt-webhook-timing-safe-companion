package dev.gaphunter.jwtwebhooktimingsafecompanion.detect

import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiReferenceExpression
import dev.gaphunter.jwtwebhooktimingsafecompanion.model.ComparisonKind
import dev.gaphunter.jwtwebhooktimingsafecompanion.model.UnsafeComparisonHit

/**
 * Finds a non-constant-time signature comparison (`x.equals(y)` or
 * `Arrays.equals(x, y)`) inside a Java method that itself computes an
 * HMAC -- the site where a locally-computed HMAC signature is compared
 * against a signature received in a webhook header/payload, using a
 * comparison that short-circuits on the first differing byte
 * (CWE-208, Observable Timing Discrepancy).
 *
 * **v0.1 scope, stated honestly:** only detects the pattern within the
 * SAME method where the HMAC is computed and the comparison happens --
 * never follows a signature value passed to another method for
 * comparison. A method already using `MessageDigest.isEqual` anywhere
 * in its body is assumed already safe and is never flagged (even if a
 * second, separate unsafe comparison also exists in the same method --
 * documented limit, not silently over-claimed). Comparison sites are
 * recognized by identifier naming convention (`sig`/`hmac`/`hash`/
 * `digest`/`mac` substrings), not real data-flow from the computed HMAC
 * value -- an unrelated `.equals()`/`Arrays.equals()` call in the same
 * method that happens to not touch a signature-named identifier is
 * never flagged.
 */
object JavaUnsafeComparisonFinder {

    fun findAll(file: PsiFile): List<UnsafeComparisonHit> {
        val hits = mutableListOf<UnsafeComparisonHit>()
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                hits += hitsForMethod(method)
            }
        })
        return hits
    }

    private fun hitsForMethod(method: PsiMethod): List<UnsafeComparisonHit> {
        val bodyText = method.body?.text ?: return emptyList()
        if (!HmacComparisonSignals.computesHmac(bodyText)) return emptyList()
        if (HmacComparisonSignals.alreadyUsesConstantTimeComparison(bodyText)) return emptyList()

        val hits = mutableListOf<UnsafeComparisonHit>()
        method.body?.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(expression: PsiMethodCallExpression) {
                super.visitMethodCallExpression(expression)
                hitForDotEquals(expression)?.let { hits += it }
                hitForArraysEquals(expression)?.let { hits += it }
            }
        })
        return hits
    }

    private fun hitForDotEquals(call: PsiMethodCallExpression): UnsafeComparisonHit? {
        val methodExpr = call.methodExpression
        if (methodExpr.referenceName != "equals") return null
        val qualifier = methodExpr.qualifierExpression ?: return null
        // Arrays.equals(a, b) is handled by hitForArraysEquals -- excluded
        // here so the same call site never produces two duplicate hits
        // (one per function) for the identical expression.
        if (qualifier.text == "Arrays" || qualifier.text == "java.util.Arrays") return null
        val argument = call.argumentList.expressions.getOrNull(0) ?: return null
        if (!HmacComparisonSignals.looksLikeSignatureIdentifier(qualifier.text) &&
            !HmacComparisonSignals.looksLikeSignatureIdentifier(argument.text)
        ) {
            return null
        }
        return UnsafeComparisonHit(anchorOf(methodExpr), ComparisonKind.DOT_EQUALS)
    }

    private fun hitForArraysEquals(call: PsiMethodCallExpression): UnsafeComparisonHit? {
        val methodExpr = call.methodExpression
        if (methodExpr.referenceName != "equals") return null
        val qualifier = methodExpr.qualifierExpression ?: return null
        if (qualifier.text != "Arrays" && qualifier.text != "java.util.Arrays") return null
        val args = call.argumentList.expressions
        if (args.size < 2) return null
        if (!HmacComparisonSignals.looksLikeSignatureIdentifier(args[0].text) &&
            !HmacComparisonSignals.looksLikeSignatureIdentifier(args[1].text)
        ) {
            return null
        }
        return UnsafeComparisonHit(anchorOf(methodExpr), ComparisonKind.ARRAYS_EQUALS)
    }

    /**
     * Anchors on the method NAME identifier (e.g. "equals"), not the
     * whole call expression -- descending blindly via firstChild can
     * land on an empty `PsiReferenceParameterList` node (present even
     * with no explicit generics), which the platform rejects with
     * "Empty PSI elements must not be passed to createDescriptor".
     * `referenceNameElement` is always a real, non-empty identifier leaf.
     */
    private fun anchorOf(methodExpr: PsiReferenceExpression): PsiElement = methodExpr.referenceNameElement ?: methodExpr
}
