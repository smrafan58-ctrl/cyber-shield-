import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * GeminiJavaService — Pure Java 17 HTTP client for Google Gemini REST APIs.
 * Handles multi-turn cybersecurity chat (gemini-3.8-flash, gemini-3.1-flash-lite, gemini-4-argon)
 * and microphone audio transcription (gemini-3.5-transcribe) directly from Java.
 */
public class GeminiJavaService {

    public static final String TRANSCRIBE_MODEL = "gemini-3.5-transcribe";
    private static final String GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";

    private final HttpClient httpClient;

    public GeminiJavaService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public String generateContent(String model, String apiKey, String jsonPayload) {
        if (apiKey == null || apiKey.isBlank() || "MY_GEMINI_API_KEY".equals(apiKey.trim())) {
            return null;
        }
        try {
            String endpoint = GEMINI_BASE_URL + model + ":generateContent";
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofMillis(1800))
                .header("Content-Type", "application/json")
                .header("x-goog-api-key", apiKey.trim())
                .header("User-Agent", "aistudio-build")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload, StandardCharsets.UTF_8))
                .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                return CyberShieldServer.extractGeminiCandidateText(resp.body());
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public String transcribeAudio(String apiKey, String jsonPayload) {
        return generateContent(TRANSCRIBE_MODEL, apiKey, jsonPayload);
    }
}
