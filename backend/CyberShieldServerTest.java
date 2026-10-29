import java.util.List;

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

        // 7. Multi-turn Gemini chat parsing, model selection, and system instruction formatting
        assertTrue("gemini-3.8-flash".equals(CyberShieldServer.normalizeGeminiModel(null)), "Default model must be gemini-3.8-flash");
        assertTrue("gemini-3.1-flash-lite".equals(CyberShieldServer.normalizeGeminiModel("gemini-3.1-flash-lite")), "Must support gemini-3.1-flash-lite");
        assertTrue("gemini-4-argon".equals(CyberShieldServer.normalizeGeminiModel("gemini-4-argon")), "Must support gemini-4-argon");

        String chatRequestBody = "{\"model\":\"gemini-3.8-flash\",\"rolePreset\":\"threat-analyst\",\"messages\":[{\"role\":\"user\",\"text\":\"Why is paypa1-example.com risky?\"},{\"role\":\"model\",\"text\":\"It uses character substitution.\"},{\"role\":\"user\",\"text\":\"What should I do next?\"}]}";
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

        // 8. Audio transcription payload builder for gemini-3.5-transcribe
        assertTrue("gemini-3.5-transcribe".equals(CyberShieldServer.GEMINI_TRANSCRIBE_MODEL), "Audio transcription model must be gemini-3.5-transcribe");
        String transcribePayload = CyberShieldServer.buildGeminiTranscribePayload("UklGRiQAAABXQVZFZm10IBAAAAABAAEA", "audio/webm", "Transcribe this audio.");
        assertTrue(transcribePayload.contains("\"inlineData\""), "Transcribe payload must contain inlineData part");
        assertTrue(transcribePayload.contains("\"mimeType\":\"audio/webm\""), "Transcribe payload must include audio mimeType");
        assertTrue(transcribePayload.contains("Transcribe this audio."), "Transcribe payload must include transcription instruction");

        System.out.println("PASS: All 8 Java Backend URL Analysis, Gemini Multi-Turn Chat & Audio Transcription assertions passed!");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }
}
