package dev.gaphunter.jwtwebhooktimingsafecompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class TimingSafeComparisonInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(TimingSafeComparisonInspection::class.java)
    }

    fun `test dot-equals comparison of a signature in an HMAC-computing method is flagged`() {
        myFixture.configureByText(
            "WebhookHandler.java",
            """
            import javax.crypto.Mac;

            class WebhookHandler {
                boolean verify(String receivedSignature, byte[] key, byte[] payload) throws Exception {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    String computedSignature = "deadbeef";
                    return computedSignature.equals(receivedSignature);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("Observable Timing Discrepancy") == true })
    }

    fun `test Arrays equals comparison of a signature in an HMAC-computing method is flagged`() {
        myFixture.configureByText(
            "WebhookHandler2.java",
            """
            import javax.crypto.Mac;
            import java.util.Arrays;

            class WebhookHandler2 {
                boolean verify(byte[] receivedSig, byte[] key, byte[] payload) throws Exception {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    byte[] computedHmac = mac.doFinal(payload);
                    return Arrays.equals(computedHmac, receivedSig);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("Observable Timing Discrepancy") == true })
    }

    fun `test a method already using MessageDigest isEqual is never flagged`() {
        myFixture.configureByText(
            "SafeHandler.java",
            """
            import javax.crypto.Mac;
            import java.security.MessageDigest;

            class SafeHandler {
                boolean verify(byte[] receivedSig, byte[] key, byte[] payload) throws Exception {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    byte[] computedHmac = mac.doFinal(payload);
                    return MessageDigest.isEqual(computedHmac, receivedSig);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Observable Timing Discrepancy") == true })
    }

    fun `test a method with no HMAC computation is never flagged even with equals calls`() {
        myFixture.configureByText(
            "NotAWebhook.java",
            """
            class NotAWebhook {
                boolean check(String a, String b) {
                    return a.equals(b);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Observable Timing Discrepancy") == true })
    }

    fun `test an unrelated equals call in an HMAC-computing method is not flagged`() {
        myFixture.configureByText(
            "WebhookHandler3.java",
            """
            import javax.crypto.Mac;

            class WebhookHandler3 {
                boolean verify(String eventType, byte[] key, byte[] payload) throws Exception {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    return eventType.equals("payment.succeeded");
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Observable Timing Discrepancy") == true })
    }

    fun `test a non-java file is never scanned`() {
        myFixture.configureByText(
            "notes.txt",
            "Mac.getInstance(\"HmacSHA256\"); computedSig.equals(receivedSig);",
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("Observable Timing Discrepancy") == true })
    }
}
