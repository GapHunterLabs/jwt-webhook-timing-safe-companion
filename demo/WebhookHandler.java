import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

class WebhookHandler {

    // Flagged: dot-equals comparison of an HMAC signature.
    boolean verifyUnsafe(String receivedSignature, byte[] key, byte[] payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String computedSignature = bytesToHex(mac.doFinal(payload));
        return computedSignature.equals(receivedSignature);
    }

    // Flagged: Arrays.equals comparison of an HMAC signature.
    boolean verifyUnsafeBytes(byte[] receivedSig, byte[] key, byte[] payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] computedHmac = mac.doFinal(payload);
        return Arrays.equals(computedHmac, receivedSig);
    }

    // Not flagged: constant-time comparison.
    boolean verifySafe(byte[] receivedSig, byte[] key, byte[] payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] computedHmac = mac.doFinal(payload);
        return MessageDigest.isEqual(computedHmac, receivedSig);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
