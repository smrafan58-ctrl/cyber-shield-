public class CyberShieldServerTest {
    public static void main(String[] args) {
        // 1. Reject empty input
        String emptyJson = CyberShieldServer.analyzeUrlInJava("   ");
        assertTrue(emptyJson.contains("\"valid\":false"), "Empty URL must be rejected");

        // 2. Reject dangerous protocol
        String jsJson = CyberShieldServer.analyzeUrlInJava("javascript:alert(1)");
        assertTrue(jsJson.contains("\"valid\":false"), "javascript: protocol must be rejected");
        assertTrue(jsJson.contains("Unsupported Protocol"), "Must explain unsupported protocol");

        // 3. Benign baseline: wikipedia.org -> score 0
        String wikiJson = CyberShieldServer.analyzeUrlInJava("https://www.wikipedia.org/");
        assertTrue(wikiJson.contains("\"valid\":true"), "wikipedia.org must be valid");
        assertTrue(wikiJson.contains("\"riskScore\":0"), "wikipedia.org must have riskScore 0");
        assertTrue(wikiJson.contains("\"classification\":\"LOW RISK INDICATORS\""), "Classification must be LOW RISK INDICATORS");

        // 4. Subdomain brand spoof: google.com.security-check.example.org
        String spoofJson = CyberShieldServer.analyzeUrlInJava("https://google.com.security-check.example.org/");
        assertTrue(spoofJson.contains("\"valid\":true"), "Spoof URL must be valid");
        assertTrue(spoofJson.contains("\"brand-impersonation\""), "Must detect brand-impersonation");
        assertTrue(spoofJson.contains("\"registrableDomain\":\"example.org\""), "Registrable domain must be example.org");

        // 5. Typosquatting login: paypa1-example.com/login -> score 40
        String typoJson = CyberShieldServer.analyzeUrlInJava("https://paypa1-example.com/login");
        assertTrue(typoJson.contains("\"valid\":true"), "Typosquat URL must be valid");
        assertTrue(typoJson.contains("\"riskScore\":40"), "paypa1-example.com/login must have riskScore 40");
        assertTrue(typoJson.contains("\"typosquatting-signal\""), "Must detect typosquatting-signal");

        // 6. Query parameter redaction
        String redactJson = CyberShieldServer.analyzeUrlInJava("https://example.com/Callback?token=secret999");
        assertTrue(!redactJson.contains("secret999") || redactJson.contains("\"redactedUrl\":\"https://example.com/Callback?token=[REDACTED]\""),
            "Redacted URL must mask query values");

        System.out.println("PASS: All 6 Java Backend URL Analysis Engine assertions passed!");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }
}
