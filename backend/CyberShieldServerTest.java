import java.util.List;

public class CyberShieldServerTest {
    public static void main(String[] args) {
        // 1. Reject empty input and control characters
        String emptyJson = CyberShieldServer.analyzeUrlInJava("   ");
        assertTrue(emptyJson.contains("\"valid\":false"), "Empty URL must be rejected");

        String ctrlJson = CyberShieldServer.analyzeUrlInJava("https://example.com/\u0000login");
        assertTrue(ctrlJson.contains("\"valid\":false"), "Control characters in URL must be rejected");

        String backslashJson = CyberShieldServer.analyzeUrlInJava("https://trusted.com\\@evil.com/login");
        assertTrue(backslashJson.contains("\"valid\":false"), "Backslashes in authority must be rejected");

        // 2. Reject dangerous protocol
        String jsJson = CyberShieldServer.analyzeUrlInJava("javascript:alert(1)");
        assertTrue(jsJson.contains("\"valid\":false"), "javascript: protocol must be rejected");
        assertTrue(jsJson.contains("Unsupported Protocol"), "Must explain unsupported protocol");

        // 3. Benign baseline: wikipedia.org -> score 0
        String wikiJson = CyberShieldServer.analyzeUrlInJava("https://www.wikipedia.org/");
        assertTrue(wikiJson.contains("\"valid\":true"), "wikipedia.org must be valid");
        assertTrue(wikiJson.contains("\"riskScore\":0"), "wikipedia.org must have riskScore 0");
        assertTrue(wikiJson.contains("\"classification\":\"LOW RISK INDICATORS\""), "Classification must be LOW RISK INDICATORS");
        assertTrue(!wikiJson.contains("backendEngine") && !wikiJson.contains("javaVersion"), "Must not expose internal JVM or engine telemetry");

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

        // 6. Strict query parameter, API key, and authority credential redaction (zero leakage anywhere in JSON or HTML)
        String secretScanJson = CyberShieldServer.analyzeUrlInJava(
            "https://admin:SuperSecretPass999@example.com/Callback?api_key=AIzaSySecretKey1234567890&token=secret999"
        );
        assertTrue(!secretScanJson.contains("SuperSecretPass999"), "Authority password must never appear in JSON output");
        assertTrue(!secretScanJson.contains("AIzaSySecretKey1234567890"), "API key in query must never appear in JSON output");
        assertTrue(!secretScanJson.contains("secret999"), "Query token value must never appear in JSON output");
        assertTrue(secretScanJson.contains("\"redactedUrl\":\"https://example.com/Callback?api_key=[REDACTED]&token=[REDACTED]\""),
            "Redacted URL must mask all query values");

        String redactedInput = CyberShieldServer.redactSensitiveInput("https://user:myPass123@example.com/api?key=AIzaSyTestKey123456789");
        assertTrue(!redactedInput.contains("myPass123") && !redactedInput.contains("AIzaSyTestKey123456789"),
            "redactSensitiveInput must strip credentials and API keys");

        // 7. Multi-turn Gemini chat parsing, model selection, and system instruction formatting
        assertTrue("gemini-3-flash-preview".equals(CyberShieldServer.normalizeGeminiModel(null)), "Default model must be gemini-3-flash-preview");
        assertTrue("gemini-3.1-flash-lite-preview".equals(CyberShieldServer.normalizeGeminiModel("gemini-3.1-flash-lite-preview")), "Must support gemini-3.1-flash-lite-preview");
        assertTrue("gemini-3.1-pro-preview".equals(CyberShieldServer.normalizeGeminiModel("gemini-3.1-pro-preview")), "Must support gemini-3.1-pro-preview");

        String chatRequestBody = "{\"model\":\"gemini-3-flash-preview\",\"rolePreset\":\"threat-analyst\",\"messages\":[{\"role\":\"user\",\"text\":\"Why is paypa1-example.com risky?\"},{\"role\":\"model\",\"text\":\"It uses character substitution.\"},{\"role\":\"user\",\"text\":\"What should I do next?\"}]}";
        List<CyberShieldServer.ChatTurn> turns = CyberShieldServer.parseChatMessagesFromJson(chatRequestBody);
        assertTrue(turns.size() == 3, "Must parse all 3 multi-turn chat messages");
        assertTrue("user".equals(turns.get(0).role) && "model".equals(turns.get(1).role), "Must preserve user and model turn roles");

        String sysInst = CyberShieldServer.buildRoleSystemInstruction("scam-educator", "Hostname: paypa1-example.com, Score: 40/100");
        String geminiPayload = CyberShieldServer.buildGeminiRequestPayload(sysInst, turns);
        assertTrue(geminiPayload.contains("\"systemInstruction\""), "Payload must include systemInstruction");
        assertTrue(geminiPayload.contains("Scam & Phishing Educator"), "System instruction must reflect selected role");
        assertTrue(geminiPayload.contains("\"contents\""), "Payload must include multi-turn contents array");

        String mockGeminiResp = "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Never enter credentials on lookalike domains.\"}],\"role\":\"model\"}}]}";
        String extracted = CyberShieldServer.extractGeminiCandidateText(mockGeminiResp);
        assertTrue("Never enter credentials on lookalike domains.".equals(extracted), "Must extract candidate text cleanly");

        // 8. Audio transcription payload builder
        String transcribePayload = CyberShieldServer.buildGeminiTranscribePayload("UklGRiQAAABXQVZFZm10IBAAAAABAAEA", "audio/webm", "Transcribe this audio.");
        assertTrue(transcribePayload.contains("\"inlineData\""), "Transcribe payload must contain inlineData part");
        assertTrue(transcribePayload.contains("\"mimeType\":\"audio/webm\""), "Transcribe payload must include audio mimeType");
        assertTrue(transcribePayload.contains("Transcribe this audio."), "Transcribe payload must include transcription instruction");

        // 9. ScanHistoryJavaStore caps at 5 analyzed URLs and deduplicates
        CyberShieldServer.HISTORY_STORE.clear();
        for (int i = 1; i <= 7; i++) {
            CyberShieldServer.analyzeUrlInJava("https://site" + i + ".example.com");
        }
        assertTrue(CyberShieldServer.HISTORY_STORE.size() == 5, "ScanHistoryJavaStore must cap strictly at 5 analyzed URLs");
        String historyJson = CyberShieldServer.HISTORY_STORE.toJsonArray();
        assertTrue(historyJson.contains("site7.example.com") && !historyJson.contains("site1.example.com"), "ScanHistoryJavaStore must retain newest 5 items");

        // 10. Web UI rendering & TXT report export verification (zero unwanted telemetry)
        ScanResultModel.AnalysisOutcome spoofOutcome = CyberShieldServer.analyzeUrlStructured("https://google.com.security-check.example.org?api_key=AIzaSyHiddenKey99999999");
        assertTrue(spoofOutcome.valid && spoofOutcome.result != null, "Structured outcome must be valid");
        String txtReport = ScanResultModel.formatTxtReport(spoofOutcome.result);
        assertTrue(txtReport.contains("Registrable Domain : example.org"), "TXT report must include extracted registrable domain");
        assertTrue(!txtReport.contains("AIzaSyHiddenKey99999999"), "TXT report must never contain raw API key");
        assertTrue(txtReport.contains(CyberShieldServer.MANDATORY_DISCLAIMER), "TXT report must include mandatory disclaimer");

        String scannerHtml = CyberShieldWebUi.renderScannerPage(
            "https://example.com?api_key=AIzaSySecretKey00000000",
            null,
            null,
            CyberShieldServer.HISTORY_STORE.getRecentScans(),
            false,
            "threat-analyst",
            "gemini-3-flash-preview",
            List.of(),
            null,
            CyberShieldServer.MANDATORY_DISCLAIMER
        );
        assertTrue(scannerHtml.contains("Is This Link Safe"), "Web UI must render scanner page hero");
        assertTrue(scannerHtml.contains("Recent Scan History"), "Web UI must render Recent Scan History");
        assertTrue(!scannerHtml.contains("AIzaSySecretKey00000000"), "Scanner HTML must redact API keys in input");
        assertTrue(!scannerHtml.contains("ScanHistoryJavaStore") && !scannerHtml.contains("Java 17 Engine"), "Scanner HTML must not show unwanted internal engine labels");

        String resultsHtml = CyberShieldWebUi.renderResultsPage(
            spoofOutcome.result,
            true,
            "threat-analyst",
            "gemini-3-flash-preview",
            List.of(new CyberShieldWebUi.ChatMessageView("model", "Welcome!", "12:00", "gemini-3-flash-preview")),
            null
        );
        assertTrue(resultsHtml.contains("Heuristic Threat Assessment"), "Web UI must render results dashboard");
        assertTrue(resultsHtml.contains("Possible Brand Impersonation (Google)"), "Web UI must render detected indicator");
        assertTrue(resultsHtml.contains("CyberShield Security Advisor"), "Web UI must render chat advisor drawer");
        assertTrue(!resultsHtml.contains("AIzaSyHiddenKey99999999"), "Results HTML must never leak query API keys");
        assertTrue(!resultsHtml.contains("Domain Registration Age"), "Results HTML must not show unverified placeholder rows");
        assertTrue(!resultsHtml.contains("gemini-3-flash-preview"), "Results HTML must not expose internal model IDs");

        CyberShieldServer.HISTORY_STORE.clear();
        System.out.println("PASS: All 10 Java 17 Security, Redaction, History Store, Report Exporter & Web UI assertions passed!");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }
}
