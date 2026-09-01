package dev.gaphunter.jwtwebhooktimingsafecompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiJavaFile
import dev.gaphunter.jwtwebhooktimingsafecompanion.detect.JavaUnsafeComparisonFinder
import dev.gaphunter.jwtwebhooktimingsafecompanion.model.ComparisonKind
import dev.gaphunter.jwtwebhooktimingsafecompanion.model.UnsafeComparisonHit
import dev.gaphunter.jwtwebhooktimingsafecompanion.review.ReviewPrompt

/**
 * Flags a webhook/HMAC signature comparison that uses `.equals()`/
 * `Arrays.equals()` (short-circuits on the first differing byte)
 * instead of `MessageDigest.isEqual(...)` (constant-time) --
 * CWE-208, Observable Timing Discrepancy. An attacker can
 * reconstruct a valid HMAC signature byte-by-byte by measuring
 * response times, forging webhook events.
 *
 * Runs via `checkFile` (same shape as every other inspection in this
 * catalog); [JavaUnsafeComparisonFinder] does the real PSI walk.
 */
class TimingSafeComparisonInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null
        if (file !is PsiJavaFile) return null

        val hits = JavaUnsafeComparisonFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: UnsafeComparisonHit): String {
        val callShape = when (hit.kind) {
            ComparisonKind.DOT_EQUALS -> ".equals(...)"
            ComparisonKind.ARRAYS_EQUALS -> "Arrays.equals(...)"
        }
        return "Signature comparison uses $callShape (short-circuits on the first differing byte) instead of " +
            "MessageDigest.isEqual(...) -- an attacker can reconstruct a valid HMAC signature by measuring " +
            "response timing (CWE-208, Observable Timing Discrepancy)"
    }
}
