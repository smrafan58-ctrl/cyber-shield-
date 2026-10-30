import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * GeminiJavaService — Pure Java 17 HTTP client for server-side Gemini API calls.
 * Reads GEMINI_API_KEY exclusively from the server environment and passes it only
 * via request headers over HTTPS, never exposing keys in URLs, logs, or responses.
 */
public class GeminiJavaService {

    public static final String TRANSCRIBE_MODEL = "gemini-3-flash-preview";
    private static final String GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/";

    private final HttpClient httpClient;

    public GeminiJavaService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    private static String getServerApiKey() {
        String key = System.getenv("GEMINI_API_KEY");
        if (key == null) return null;
        String trimmed = key.trim();
        if (trimmed.isEmpty() || "MY_GEMINI_API_KEY".equalsIgnoreCase(trimmed) || "YOUR_API_KEY".equalsIgnoreCase(trimmed)) {
            return null;
        }
        return trimmed;
    }

    public boolean isConfigured() {
        return getServerApiKey() != null;
    }

    public String generateContent(String model, String jsonPayload) {
        String apiKey = getServerApiKey();
        if (apiKey == null) {
            return null;
        }
        String safeModel = CyberShieldServer.normalizeGeminiModel(model);
        try {
            String endpoint = GEMINI_BASE_URL + safeModel + ":generateContent";
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofMillis(1800))
                .header("Content-Type", "application/json")
                .header("x-goog-api-key", apiKey)
                .header("User-Agent", "aistudio-build")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload, StandardCharsets.UTF_8))
                .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                return CyberShieldServer.extractGeminiCandidateText(resp.body());
            }
        } catch (Exception ignored) {
            // Never log or rethrow exception details that could include request metadata
        }
        return null;
    }

    public String transcribeAudio(String jsonPayload) {
        return generateContent(TRANSCRIBE_MODEL, jsonPayload);
    }
}
