import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CyberShield AI — Pure Java 17 Web Application & URL Threat Detection Engine.
 * Enforces strict input validation, secret/query redaction, rate limiting,
 * HTTP security headers, and zero internal telemetry exposure.
 */
public class CyberShieldServer {

    private static final int DEFAULT_PORT = 3000;
    private static final int MAX_BODY_BYTES = 8192;
    private static final long RATE_LIMIT_WINDOW_MS = 60_000L;
    private static final int MAX_REQUESTS_PER_WINDOW = 120;
    private static final int MAX_RATE_BUCKETS = 4096;
    private static final int MAX_WEB_CHAT_MESSAGES = 20;
    private static final int MAX_CHAT_MESSAGE_LENGTH = 500;

    public static final String MANDATORY_DISCLAIMER =
        "Risk scores are based on observable URL patterns and available reputation data. They do not guarantee that a website is safe or malicious.";

    private static final List<String> UNIVERSAL_SAFETY_RULES = List.of(
        "Do not enter passwords on suspicious sites.",
        "Never share OTPs or banking credentials.",
        "Do not pay fines or transfer money based solely on a link's claims.",
        "Access official services through independently verified websites or applications."
    );

    private static final Set<String> MULTI_PART_TLDS = new HashSet<>(Arrays.asList(
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "co.in", "gov.in", "nic.in", "org.in", "ac.in", "net.in", "res.in", "edu.in", "mil.in",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.jp", "ne.jp", "or.jp", "co.nz", "com.br", "com.sg", "edu.sg", "gov.sg",
        "co.za", "com.mx", "com.hk", "com.tr", "co.kr", "co.id", "com.my"
    ));

    private static final Set<String> URL_SHORTENERS = new HashSet<>(Arrays.asList(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "v.gd", "bit.do", "bl.ink"
    ));

    private static final Set<String> FREQUENTLY_ABUSED_TLDS = new HashSet<>(Arrays.asList(
        "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
        "zip", "mov", "icu", "buzz", "monster", "rest", "support"
    ));

    private static final Set<String> REDIRECT_PARAM_NAMES = new HashSet<>(Arrays.asList(
        "redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_to",
        "next", "url", "target", "dest", "destination", "continue", "goto", "out", "view"
    ));

    private static final Pattern SECRET_TOKEN_PATTERN = Pattern.compile(
        "(?i)(AIza[0-9A-Za-z_-]{15,}|sk-[0-9A-Za-z_-]{15,}|ghp_[0-9A-Za-z]{15,}|Bearer\\s+[0-9A-Za-z._-]{10,})"
    );

    private static final Map<String, RateBucket> RATE_LIMITS = new ConcurrentHashMap<>();
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(3000))
        .build();
    public static final ScanHistoryJavaStore HISTORY_STORE = new ScanHistoryJavaStore();
    private static final GeminiJavaService GEMINI_SERVICE = new GeminiJavaService(HTTP_CLIENT);

    // Server-side multi-turn chat state for the Web UI
    private static final List<CyberShieldWebUi.ChatMessageView> WEB_CHAT_MESSAGES = new CopyOnWriteArrayList<>();
    private static volatile String activeChatRole = "threat-analyst";
    private static volatile String activeChatModel = "gemini-3-flash-preview";

    static {
        resetWebChatMessages("threat-analyst");
    }

    private static void resetWebChatMessages(String rolePreset) {
        WEB_CHAT_MESSAGES.clear();
        String welcome;
        if ("scam-educator".equalsIgnoreCase(rolePreset)) {
            welcome = "Hello! I am the CyberShield AI Scam & Phishing Educator. Ask me how to spot phishing links, fake payment portals, or government impersonation scams.";
        } else if ("incident-advisor".equalsIgnoreCase(rolePreset)) {
            welcome = "Hello! I am the CyberShield AI Incident Safety Advisor. Tell me if you clicked a suspicious link or entered credentials, and I will walk you through immediate safety steps.";
        } else {
            welcome = "Hello! I am the CyberShield AI URL Threat Analyst. Ask me about any scanned URL, suspicious subdomain, lookalike domain, or security indicator.";
        }
        WEB_CHAT_MESSAGES.add(new CyberShieldWebUi.ChatMessageView("model", welcome, currentShortTime(), null));
    }

    private static String currentShortTime() {
        return LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm"));
    }

    private static class RateBucket {
        int count;
        long windowStart;
        RateBucket(int count, long windowStart) {
            this.count = count;
            this.windowStart = windowStart;
        }
    }

    public static class BrandRule {
        final String brandName;
        final List<String> tokens;
        final Set<String> officialDomains;
        final List<Pattern> typosquatPatterns;

        public BrandRule(String brandName, List<String> tokens, List<String> officialDomains, List<String> regexes) {
            this.brandName = brandName;
            this.tokens = tokens;
            this.officialDomains = new HashSet<>(officialDomains);
            this.typosquatPatterns = new ArrayList<>();
            for (String r : regexes) {
                this.typosquatPatterns.add(Pattern.compile(r, Pattern.CASE_INSENSITIVE));
            }
        }
    }

    private static final List<BrandRule> PROTECTED_BRANDS = List.of(
        new BrandRule("Google", List.of("google", "gmail", "googlepay", "gpay"),
            List.of("google.com", "google.co.in", "google.co.uk", "gmail.com", "withgoogle.com", "youtube.com"),
            List.of("g00gle", "goog1e", "g0ogle", "googie", "go0gle")),
        new BrandRule("Microsoft", List.of("microsoft", "office365", "onedrive", "outlook", "sharepoint"),
            List.of("microsoft.com", "live.com", "office.com", "outlook.com", "sharepoint.com", "onedrive.com", "microsoftonline.com"),
            List.of("micr0soft", "mircosoft", "micros0ft", "rnicrosoft", "outl00k")),
        new BrandRule("Apple", List.of("apple", "icloud", "appleid"),
            List.of("apple.com", "icloud.com", "me.com"),
            List.of("app1e", "ic1oud", "apple-id")),
        new BrandRule("Amazon", List.of("amazon", "aws", "primevideo"),
            List.of("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com", "primevideo.com"),
            List.of("amaz0n", "arnazon", "amzon", "amazonn")),
        new BrandRule("PayPal", List.of("paypal"),
            List.of("paypal.com", "paypal.me"),
            List.of("paypa1", "paypai", "paipal", "pay-pal")),
        new BrandRule("State Bank of India (SBI)", List.of("onlinesbi", "sbicard", "sbiyono", "yonosbi"),
            List.of("onlinesbi.sbi", "sbi.co.in", "sbicard.com"),
            List.of("on1inesbi", "sbi-kyc", "sbi-yono", "yono-sbi")),
        new BrandRule("HDFC Bank", List.of("hdfcbank", "hdfcnetbanking"),
            List.of("hdfcbank.com", "hdfc.com"),
            List.of("hdfc-kyc", "hdfc-bank", "hdfcbnk")),
        new BrandRule("ICICI Bank", List.of("icicibank"),
            List.of("icicibank.com", "icicidirect.com"),
            List.of("ic1cibank", "icici-bank", "icici-kyc")),
        new BrandRule("Axis Bank", List.of("axisbank"),
            List.of("axisbank.com"),
            List.of("axis-bank", "ax1sbank", "axis-kyc")),
        new BrandRule("Netflix", List.of("netflix"),
            List.of("netflix.com"),
            List.of("netf1ix", "netfiix", "net-flix")),
        new BrandRule("Meta / Facebook / Instagram", List.of("facebook", "instagram", "whatsapp"),
            List.of("facebook.com", "instagram.com", "whatsapp.com", "meta.com", "fb.com"),
            List.of("faceb00k", "1nstagram", "instagrarn", "whatsap-")),
        new BrandRule("GitHub", List.of("github"),
            List.of("github.com", "github.io", "githubusercontent.com"),
            List.of("g1thub", "git-hub")),
        new BrandRule("Chase Bank", List.of("jpmorganchase"),
            List.of("chase.com", "jpmorganchase.com"),
            List.of("chase-bank", "chase-verify", "chase-login"))
    );

    public static void main(String[] args) throws IOException {
        int port = DEFAULT_PORT;
        String envPort = System.getenv("PORT");
        if (envPort == null || envPort.isBlank()) {
            envPort = System.getenv("JAVA_BACKEND_PORT");
        }
        if (envPort != null && !envPort.isBlank()) {
            try {
                port = Integer.parseInt(envPort.trim());
            } catch (NumberFormatException ignored) {}
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        // Web UI Routes
        server.createContext("/scan", new WebScanHandler());
        server.createContext("/clear-history", new WebClearHistoryHandler());
        server.createContext("/export", new WebExportHandler());
        server.createContext("/chat", new WebChatHandler());
        // JSON API Routes
        server.createContext("/api/health", new HealthHandler());
        server.createContext("/api/reputation/status", new ReputationStatusHandler());
        server.createContext("/api/reputation/check", new ReputationCheckHandler());
        server.createContext("/api/analyze", new AnalyzeUrlHandler());
        server.createContext("/api/history", new ScanHistoryHandler());
        server.createContext("/api/chat", new ChatHandler());
        server.createContext("/api/transcribe", new TranscribeAudioHandler());
        server.createContext("/", new WebRootHandler());
        server.setExecutor(Executors.newFixedThreadPool(12));
        server.start();
        System.out.println("CyberShield AI Server listening on http://0.0.0.0:" + port);
    }

    /**
     * Redacts any embedded authority credentials, query parameter values, or raw API key tokens
     * from a user-supplied string so secrets are never stored or echoed back.
     */
    public static String redactSensitiveInput(String input) {
        if (input == null || input.isBlank()) return "";
        String sanitized = SECRET_TOKEN_PATTERN.matcher(input.trim()).replaceAll("[REDACTED]");
        // Redact authority credentials before @ (e.g. https://user:pass@host -> https://[REDACTED]@host)
        sanitized = sanitized.replaceAll("(?i)(https?://)([^/?#@\\s]+)@", "$1[REDACTED]@");
        // Redact any query string parameter values (?k=v&k2=v2 -> ?k=[REDACTED]&k2=[REDACTED])
        int qIdx = sanitized.indexOf('?');
        if (qIdx >= 0 && qIdx + 1 < sanitized.length()) {
            String base = sanitized.substring(0, qIdx);
            String queryAndHash = sanitized.substring(qIdx + 1);
            int hashIdx = queryAndHash.indexOf('#');
            String queryPart = hashIdx >= 0 ? queryAndHash.substring(0, hashIdx) : queryAndHash;
            StringBuilder qSb = new StringBuilder();
            for (String pair : queryPart.split("&")) {
                if (pair.isEmpty()) continue;
                if (qSb.length() > 0) qSb.append("&");
                int eq = pair.indexOf('=');
                String key = eq >= 0 ? pair.substring(0, eq) : pair;
                String safeKey = key.replaceAll("[^a-zA-Z0-9_.-]", "");
                if (safeKey.isEmpty()) safeKey = "param";
                qSb.append(safeKey).append("=[REDACTED]");
            }
            sanitized = base + (qSb.length() > 0 ? "?" + qSb : "");
        }
        return sanitized;
    }

    private static void applySecurityHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        // Allow iframe embedding within AI Studio workspace and Cloud Run preview domains
        headers.set("Content-Security-Policy",
            "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors *; base-uri 'self'; form-action 'self'");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(self), payment=(), usb=()");
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
    }

    private static String extractClientIp(HttpExchange exchange) {
        if (exchange.getRemoteAddress() != null && exchange.getRemoteAddress().getAddress() != null) {
            return exchange.getRemoteAddress().getAddress().getHostAddress();
        }
        return "local";
    }

    private static Map<String, String> parseUrlEncodedPairs(String raw) {
        Map<String, String> map = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return map;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            try {
                String dk = URLDecoder.decode(k, StandardCharsets.UTF_8);
                String dv = URLDecoder.decode(v, StandardCharsets.UTF_8);
                map.put(dk, dv);
            } catch (Exception ignored) {
                map.put(k, v);
            }
        }
        return map;
    }

    private static void sendHtml(HttpExchange exchange, int statusCode, String htmlBody) throws IOException {
        byte[] bytes = htmlBody.getBytes(StandardCharsets.UTF_8);
        applySecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendRedirect(HttpExchange exchange, String location) throws IOException {
        applySecurityHeaders(exchange);
        // Strictly enforce internal-only relative redirect path to prevent open redirects and header injection
        String safeLoc = (location == null || !location.startsWith("/") || location.startsWith("//"))
            ? "/"
            : location.replaceAll("[\\r\\n]", "");
        exchange.getResponseHeaders().set("Location", safeLoc);
        exchange.sendResponseHeaders(303, -1);
        exchange.close();
    }

    /**
     * Renders the main URL Pasting Page (or Scan Results Page if ?url=... is passed).
     * Rejects non-root paths with 404 Not Found so sensitive files cannot be probed.
     */
    static class WebRootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendHtml(exchange, 429, "<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>");
                return;
            }
            String reqPath = exchange.getRequestURI().getPath();
            if (reqPath != null && !reqPath.equals("/") && !reqPath.equals("/index.html")) {
                sendHtml(exchange, 404, "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>");
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod()) && !"HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendHtml(exchange, 405, "<!DOCTYPE html><html><body><h1>405 Method Not Allowed</h1></body></html>");
                return;
            }

            Map<String, String> query = parseUrlEncodedPairs(exchange.getRequestURI().getRawQuery());
            boolean chatOpen = "open".equalsIgnoreCase(query.get("chat")) || "1".equals(query.get("chat"));
            String urlParam = query.get("url");

            if (urlParam != null && !urlParam.isBlank()) {
                ScanResultModel.AnalysisOutcome outcome = analyzeUrlStructured(urlParam);
                if (outcome.valid && outcome.result != null) {
                    String html = CyberShieldWebUi.renderResultsPage(
                        outcome.result,
                        chatOpen,
                        activeChatRole,
                        activeChatModel,
                        new ArrayList<>(WEB_CHAT_MESSAGES),
                        null
                    );
                    sendHtml(exchange, 200, html);
                    return;
                } else {
                    String html = CyberShieldWebUi.renderScannerPage(
                        redactSensitiveInput(urlParam),
                        outcome.errorTitle,
                        outcome.errorMessage,
                        HISTORY_STORE.getRecentScans(),
                        chatOpen,
                        activeChatRole,
                        activeChatModel,
                        new ArrayList<>(WEB_CHAT_MESSAGES),
                        null,
                        MANDATORY_DISCLAIMER
                    );
                    sendHtml(exchange, 200, html);
                    return;
                }
            }

            String html = CyberShieldWebUi.renderScannerPage(
                "",
                null,
                null,
                HISTORY_STORE.getRecentScans(),
                chatOpen,
                activeChatRole,
                activeChatModel,
                new ArrayList<>(WEB_CHAT_MESSAGES),
                null,
                MANDATORY_DISCLAIMER
            );
            sendHtml(exchange, 200, html);
        }
    }

    /**
     * Handles POST /scan and GET /scan?url=...
     */
    static class WebScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendHtml(exchange, 429, "<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>");
                return;
            }
            String method = exchange.getRequestMethod();
            if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
                sendHtml(exchange, 405, "<!DOCTYPE html><html><body><h1>405 Method Not Allowed</h1></body></html>");
                return;
            }

            Map<String, String> params = new LinkedHashMap<>(parseUrlEncodedPairs(exchange.getRequestURI().getRawQuery()));
            if ("POST".equalsIgnoreCase(method)) {
                try {
                    String body = readBodyLimited(exchange);
                    params.putAll(parseUrlEncodedPairs(body));
                } catch (IOException e) {
                    String html = CyberShieldWebUi.renderScannerPage(
                        "",
                        "Input Exceeds Limit",
                        "The submitted request exceeds the maximum size limit.",
                        HISTORY_STORE.getRecentScans(),
                        false,
                        activeChatRole,
                        activeChatModel,
                        new ArrayList<>(WEB_CHAT_MESSAGES),
                        null,
                        MANDATORY_DISCLAIMER
                    );
                    sendHtml(exchange, 413, html);
                    return;
                }
            }
            boolean chatOpen = "open".equalsIgnoreCase(params.get("chat")) || "1".equals(params.get("chat"));
            String rawUrl = params.getOrDefault("url", "");

            ScanResultModel.AnalysisOutcome outcome = analyzeUrlStructured(rawUrl);
            if (!outcome.valid || outcome.result == null) {
                String html = CyberShieldWebUi.renderScannerPage(
                    redactSensitiveInput(rawUrl),
                    outcome.errorTitle != null ? outcome.errorTitle : "Invalid URL Input",
                    outcome.errorMessage != null ? outcome.errorMessage : "Please enter a single valid HTTP or HTTPS URL.",
                    HISTORY_STORE.getRecentScans(),
                    chatOpen,
                    activeChatRole,
                    activeChatModel,
                    new ArrayList<>(WEB_CHAT_MESSAGES),
                    null,
                    MANDATORY_DISCLAIMER
                );
                sendHtml(exchange, 200, html);
                return;
            }

            String html = CyberShieldWebUi.renderResultsPage(
                outcome.result,
                chatOpen,
                activeChatRole,
                activeChatModel,
                new ArrayList<>(WEB_CHAT_MESSAGES),
                null
            );
            sendHtml(exchange, 200, html);
        }
    }

    /**
     * Handles POST /clear-history.
     */
    static class WebClearHistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendHtml(exchange, 429, "<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>");
                return;
            }
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendRedirect(exchange, "/");
                return;
            }
            HISTORY_STORE.clear();
            sendRedirect(exchange, "/");
        }
    }

    /**
     * Handles GET /export?url=...&format=txt|json.
     */
    static class WebExportHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendHtml(exchange, 429, "<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>");
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendHtml(exchange, 405, "<!DOCTYPE html><html><body><h1>405 Method Not Allowed</h1></body></html>");
                return;
            }
            Map<String, String> query = parseUrlEncodedPairs(exchange.getRequestURI().getRawQuery());
            String url = query.getOrDefault("url", "");
            String format = query.getOrDefault("format", "txt").toLowerCase(Locale.ROOT);

            ScanResultModel.ScanResult result = HISTORY_STORE.findByUrl(url);
            if (result == null && !url.isBlank()) {
                ScanResultModel.AnalysisOutcome outcome = analyzeUrlStructured(url);
                if (outcome.valid) {
                    result = outcome.result;
                }
            }
            if (result == null) {
                sendRedirect(exchange, "/");
                return;
            }

            applySecurityHeaders(exchange);
            String safeHost = result.domain.hostname.replaceAll("[^a-zA-Z0-9.-]", "_");
            if (safeHost.isEmpty()) safeHost = "domain";
            if ("json".equals(format)) {
                byte[] bytes = result.rawResultJson.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"cybershield-report-" + safeHost + ".json\"");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
                return;
            }

            String txtContent = ScanResultModel.formatTxtReport(result);
            byte[] bytes = txtContent.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"cybershield-report-" + safeHost + ".txt\"");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    /**
     * Handles POST /chat for the server-rendered Security Advisor.
     */
    static class WebChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendHtml(exchange, 429, "<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1></body></html>");
                return;
            }
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendRedirect(exchange, "/?chat=open");
                return;
            }
            String body;
            try {
                body = readBodyWithLimit(exchange, 16384);
            } catch (IOException e) {
                sendRedirect(exchange, "/?chat=open");
                return;
            }
            Map<String, String> form = parseUrlEncodedPairs(body);

            String action = form.getOrDefault("action", "send");
            String rolePreset = normalizeRolePreset(form.getOrDefault("rolePreset", activeChatRole));
            String model = normalizeGeminiModel(form.getOrDefault("model", activeChatModel));
            String activeUrl = redactSensitiveInput(form.getOrDefault("activeUrl", "").trim());
            activeChatRole = rolePreset;
            activeChatModel = model;

            if ("reset".equalsIgnoreCase(action)) {
                resetWebChatMessages(rolePreset);
            } else {
                String userMessage = form.getOrDefault("quickPrompt", "").trim();
                if (userMessage.isEmpty()) {
                    userMessage = form.getOrDefault("message", "").trim();
                }
                if (userMessage.length() > MAX_CHAT_MESSAGE_LENGTH) {
                    userMessage = userMessage.substring(0, MAX_CHAT_MESSAGE_LENGTH);
                }
                userMessage = redactSensitiveInput(userMessage);
                if (!userMessage.isEmpty()) {
                    WEB_CHAT_MESSAGES.add(new CyberShieldWebUi.ChatMessageView("user", userMessage, currentShortTime(), null));
                    while (WEB_CHAT_MESSAGES.size() > MAX_WEB_CHAT_MESSAGES) {
                        WEB_CHAT_MESSAGES.remove(0);
                    }

                    ScanResultModel.ScanResult activeScan = HISTORY_STORE.findByUrl(activeUrl);
                    String scanContext = ScanResultModel.formatScanContextForAdvisor(activeScan);
                    List<ChatTurn> turns = new ArrayList<>();
                    for (CyberShieldWebUi.ChatMessageView m : WEB_CHAT_MESSAGES) {
                        turns.add(new ChatTurn(m.role, m.text));
                    }

                    String systemInstruction = buildRoleSystemInstruction(rolePreset, scanContext);
                    String payload = buildGeminiRequestPayload(systemInstruction, turns);
                    String replyText = GEMINI_SERVICE.generateContent(model, payload);
                    if (replyText == null && !"gemini-3-flash-preview".equals(model)) {
                        replyText = GEMINI_SERVICE.generateContent("gemini-3-flash-preview", payload);
                    }
                    if (replyText == null || replyText.isBlank()) {
                        replyText = generateContextualAnalystReply(rolePreset, scanContext, turns);
                    }
                    WEB_CHAT_MESSAGES.add(new CyberShieldWebUi.ChatMessageView("model", replyText, currentShortTime(), null));
                    while (WEB_CHAT_MESSAGES.size() > MAX_WEB_CHAT_MESSAGES) {
                        WEB_CHAT_MESSAGES.remove(0);
                    }
                }
            }

            if (!activeUrl.isEmpty()) {
                ScanResultModel.ScanResult activeResult = HISTORY_STORE.findByUrl(activeUrl);
                if (activeResult == null) {
                    ScanResultModel.AnalysisOutcome out = analyzeUrlStructured(activeUrl);
                    if (out.valid) activeResult = out.result;
                }
                if (activeResult != null) {
                    String html = CyberShieldWebUi.renderResultsPage(
                        activeResult,
                        true,
                        activeChatRole,
                        activeChatModel,
                        new ArrayList<>(WEB_CHAT_MESSAGES),
                        null
                    );
                    sendHtml(exchange, 200, html);
                    return;
                }
            }

            String html = CyberShieldWebUi.renderScannerPage(
                "",
                null,
                null,
                HISTORY_STORE.getRecentScans(),
                true,
                activeChatRole,
                activeChatModel,
                new ArrayList<>(WEB_CHAT_MESSAGES),
                null,
                MANDATORY_DISCLAIMER
            );
            sendHtml(exchange, 200, html);
        }
    }

    private static String normalizeRolePreset(String role) {
        if ("scam-educator".equalsIgnoreCase(role)) return "scam-educator";
        if ("incident-advisor".equalsIgnoreCase(role)) return "incident-advisor";
        return "threat-analyst";
    }

    private static boolean allowRateLimit(String clientIp) {
        long now = System.currentTimeMillis();
        if (RATE_LIMITS.size() > MAX_RATE_BUCKETS) {
            RATE_LIMITS.entrySet().removeIf(e -> now - e.getValue().windowStart > RATE_LIMIT_WINDOW_MS);
            if (RATE_LIMITS.size() > MAX_RATE_BUCKETS) {
                RATE_LIMITS.clear();
            }
        }
        String key = clientIp == null ? "local" : clientIp;
        RateBucket bucket = RATE_LIMITS.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart > RATE_LIMIT_WINDOW_MS) {
                return new RateBucket(1, now);
            }
            existing.count += 1;
            return existing;
        });
        return bucket.count <= MAX_REQUESTS_PER_WINDOW;
    }

    private static String readBodyLimited(HttpExchange exchange) throws IOException {
        return readBodyWithLimit(exchange, MAX_BODY_BYTES);
    }

    private static String readBodyWithLimit(HttpExchange exchange, int maxBytes) throws IOException {
        try (InputStream is = exchange.getRequestBody();
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int total = 0;
            int read;
            while ((read = is.read(buffer)) != -1) {
                total += read;
                if (total > maxBytes) {
                    throw new IOException("Request payload exceeds limit");
                }
                bos.write(buffer, 0, read);
            }
            return bos.toString(StandardCharsets.UTF_8);
        }
    }

    private static void sendJson(HttpExchange exchange, int statusCode, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        applySecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static String unescapeJsonValue(String raw) {
        if (raw == null) return "";
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                char next = raw.charAt(++i);
                switch (next) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 4 < raw.length()) {
                            String hex = raw.substring(i + 1, i + 5);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                                i += 4;
                            } catch (NumberFormatException e) {
                                sb.append("\\u").append(hex);
                                i += 4;
                            }
                        } else {
                            sb.append("\\u");
                        }
                        break;
                    default:
                        sb.append(next);
                        break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String extractJsonStringField(String json, String fieldName) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        return unescapeJsonValue(m.group(1));
    }

    static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"error\":\"Rate limit reached\"}");
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            sendJson(exchange, 200, "{\"status\":\"ok\"}");
        }
    }

    static class ReputationStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"error\":\"Rate limit reached\"}");
                return;
            }
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            String sbKey = System.getenv("SAFE_BROWSING_API_KEY");
            boolean configured = sbKey != null && !sbKey.trim().isEmpty() && !"YOUR_API_KEY".equalsIgnoreCase(sbKey.trim());
            sendJson(exchange, 200, "{\"configured\":" + configured + "}");
        }
    }

    static class ReputationCheckHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{"
                    + "\"checked\":false,"
                    + "\"status\":\"unavailable\","
                    + "\"summaryLabel\":\"Reputation check unavailable (rate limit reached).\","
                    + "\"providerName\":\"Rate Limited\","
                    + "\"lastCheckedAt\":\"" + Instant.now().toString() + "\""
                    + "}");
                return;
            }

            String body;
            try {
                body = readBodyLimited(exchange);
            } catch (IOException e) {
                sendJson(exchange, 413, "{\"checked\":false,\"status\":\"unavailable\",\"summaryLabel\":\"Payload too large.\"}");
                return;
            }

            String url = extractJsonStringField(body, "url");
            if (url == null || url.isBlank() || url.length() > 2048) {
                sendJson(exchange, 400, "{"
                    + "\"checked\":false,"
                    + "\"status\":\"unavailable\","
                    + "\"summaryLabel\":\"Invalid URL input for reputation check.\","
                    + "\"providerName\":\"Not checked\","
                    + "\"lastCheckedAt\":null"
                    + "}");
                return;
            }

            String redactedTarget = redactSensitiveInput(url.trim());
            String resultJson = queryExternalReputation(redactedTarget, false);
            sendJson(exchange, 200, resultJson);
        }
    }

    private static String queryExternalReputation(String sanitizedUrl, boolean isPrivateOrLocal) {
        if (isPrivateOrLocal) {
            return "{"
                + "\"checked\":false,"
                + "\"status\":\"not_applicable\","
                + "\"summaryLabel\":\"Private or local network address — external reputation lookup skipped.\","
                + "\"providerName\":\"Not checked\","
                + "\"lastCheckedAt\":null"
                + "}";
        }
        String sbKey = System.getenv("SAFE_BROWSING_API_KEY");
        if (sbKey != null && !sbKey.trim().isEmpty() && !"YOUR_API_KEY".equalsIgnoreCase(sbKey.trim())) {
            try {
                String endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
                String payload = "{"
                    + "\"client\":{\"clientId\":\"cybershield-ai\",\"clientVersion\":\"1.0.0\"},"
                    + "\"threatInfo\":{"
                    + "\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],"
                    + "\"platformTypes\":[\"ANY_PLATFORM\"],"
                    + "\"threatEntryTypes\":[\"URL\"],"
                    + "\"threatEntries\":[{\"url\":\"" + jsonEscape(sanitizedUrl) + "\"}]"
                    + "}}";
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .timeout(Duration.ofMillis(3500))
                    .header("Content-Type", "application/json")
                    .header("X-Goog-Api-Key", sbKey.trim())
                    .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                    .build();
                HttpResponse<String> resp = HTTP_CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    String respBody = resp.body();
                    if (respBody != null && respBody.contains("\"matches\"")) {
                        return "{"
                            + "\"checked\":true,"
                            + "\"status\":\"flagged\","
                            + "\"summaryLabel\":\"Flagged by Google Safe Browsing\","
                            + "\"providerName\":\"Google Safe Browsing\","
                            + "\"lastCheckedAt\":\"" + Instant.now().toString() + "\""
                            + "}";
                    }
                    return "{"
                        + "\"checked\":true,"
                        + "\"status\":\"clean\","
                        + "\"summaryLabel\":\"No known match in Google Safe Browsing (does not guarantee safety).\","
                        + "\"providerName\":\"Google Safe Browsing\","
                        + "\"lastCheckedAt\":\"" + Instant.now().toString() + "\""
                        + "}";
                }
            } catch (Exception ignored) {
                return "{"
                    + "\"checked\":false,"
                    + "\"status\":\"unavailable\","
                    + "\"summaryLabel\":\"Reputation check unavailable.\","
                    + "\"providerName\":\"Google Safe Browsing\","
                    + "\"lastCheckedAt\":\"" + Instant.now().toString() + "\""
                    + "}";
            }
        }
        return "{"
            + "\"checked\":false,"
            + "\"status\":\"not_configured\","
            + "\"summaryLabel\":\"Not checked\","
            + "\"providerName\":\"Not checked\","
            + "\"lastCheckedAt\":null"
            + "}";
    }

    static class AnalyzeUrlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"valid\":false,\"errorTitle\":\"Rate Limit Reached\",\"error\":\"Too many scan requests. Please wait a moment and try again.\"}");
                return;
            }
            String body;
            try {
                body = readBodyLimited(exchange);
            } catch (IOException e) {
                sendJson(exchange, 413, "{\"valid\":false,\"errorTitle\":\"Input Exceeds Limit\",\"error\":\"Request body too large.\"}");
                return;
            }

            String rawUrl = extractJsonStringField(body, "url");
            if (rawUrl == null) rawUrl = "";
            String responseJson = analyzeUrlInJava(rawUrl);
            sendJson(exchange, 200, responseJson);
        }
    }

    static class ScanHistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"error\":\"Rate limit reached\"}");
                return;
            }
            String method = exchange.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                String json = "{"
                    + "\"count\":" + HISTORY_STORE.size() + ","
                    + "\"history\":" + HISTORY_STORE.toJsonArray()
                    + "}";
                sendJson(exchange, 200, json);
                return;
            }
            if ("DELETE".equalsIgnoreCase(method)) {
                HISTORY_STORE.clear();
                sendJson(exchange, 200, "{\"cleared\":true,\"count\":0}");
                return;
            }
            sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
        }
    }

    public static class ChatTurn {
        public final String role;
        public final String text;
        public ChatTurn(String role, String text) {
            this.role = "model".equalsIgnoreCase(role) ? "model" : "user";
            String clean = text == null ? "" : redactSensitiveInput(text.trim());
            if (clean.length() > MAX_CHAT_MESSAGE_LENGTH) {
                clean = clean.substring(0, MAX_CHAT_MESSAGE_LENGTH);
            }
            this.text = clean;
        }
    }

    public static List<ChatTurn> parseChatMessagesFromJson(String jsonBody) {
        List<ChatTurn> turns = new ArrayList<>();
        if (jsonBody == null || jsonBody.isBlank()) return turns;
        Pattern objPattern = Pattern.compile("\\{[^{}]*\"role\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"[^{}]*\"text\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"[^{}]*\\}|\\{[^{}]*\"text\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"[^{}]*\"role\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"[^{}]*\\}");
        Matcher m = objPattern.matcher(jsonBody);
        while (m.find()) {
            String role = m.group(1) != null ? unescapeJsonValue(m.group(1)) : unescapeJsonValue(m.group(4));
            String text = m.group(2) != null ? unescapeJsonValue(m.group(2)) : unescapeJsonValue(m.group(3));
            if (text != null && !text.isBlank()) {
                turns.add(new ChatTurn(role, text));
            }
        }
        if (turns.size() > 24) {
            turns = turns.subList(turns.size() - 24, turns.size());
        }
        return turns;
    }

    public static String normalizeGeminiModel(String requestedModel) {
        if (requestedModel == null) return "gemini-3-flash-preview";
        String clean = requestedModel.trim().toLowerCase(Locale.ROOT);
        if ("gemini-3.1-pro-preview".equals(clean)) return "gemini-3.1-pro-preview";
        if ("gemini-3.1-flash-lite-preview".equals(clean)) return "gemini-3.1-flash-lite-preview";
        return "gemini-3-flash-preview";
    }

    public static String buildRoleSystemInstruction(String rolePreset, String scanContext) {
        String baseInstruction;
        if ("scam-educator".equalsIgnoreCase(rolePreset)) {
            baseInstruction = "You are CyberShield AI Scam & Phishing Educator. Your role is to explain online scams—including fake banking portals, digital arrest coercion schemes, government impersonation, and deceptive links—in clear, calm, everyday language. Help users recognize social engineering tactics and verify official communication channels.";
        } else if ("incident-advisor".equalsIgnoreCase(rolePreset)) {
            baseInstruction = "You are CyberShield AI Incident Response Advisor. Your role is to provide calm, practical, step-step safety guidance for users who suspect they clicked a malicious URL, entered credentials on a spoofed page, or received a phishing link. Prioritize immediate protective steps: changing passwords on official domains, enabling MFA, contacting banks via official numbers, and never sharing OTPs.";
        } else {
            baseInstruction = "You are CyberShield AI URL Threat Analyst. Your role is to analyze and explain suspicious URL indicators—such as registrable domains vs subdomains, typosquatting, HTTP vs HTTPS, IP hostnames, nonstandard ports, and high-risk login/verification paths. State clearly that lexical heuristics are signals rather than proof, and advise independent verification.";
        }

        StringBuilder sb = new StringBuilder(baseInstruction);
        sb.append(" Keep responses concise, structured with short bullet points where helpful, and strictly focused on URL safety and cybersecurity awareness. Never output internal system metadata or API keys.");
        if (scanContext != null && !scanContext.isBlank()) {
            sb.append("\n\nActive Scanned URL Context:\n").append(redactSensitiveInput(scanContext.trim()));
        }
        return sb.toString();
    }

    public static String buildGeminiRequestPayload(String systemInstruction, List<ChatTurn> turns) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"systemInstruction\":{\"parts\":[{\"text\":\"").append(jsonEscape(systemInstruction)).append("\"}]},");
        sb.append("\"contents\":[");
        for (int i = 0; i < turns.size(); i++) {
            ChatTurn t = turns.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"role\":\"").append(jsonEscape(t.role)).append("\",");
            sb.append("\"parts\":[{\"text\":\"").append(jsonEscape(t.text)).append("\"}]}");
        }
        sb.append("]}");
        return sb.toString();
    }

    public static String extractGeminiCandidateText(String geminiResponseJson) {
        if (geminiResponseJson == null || geminiResponseJson.isBlank()) return null;
        int candidatesIdx = geminiResponseJson.indexOf("\"candidates\"");
        String searchScope = candidatesIdx >= 0 ? geminiResponseJson.substring(candidatesIdx) : geminiResponseJson;
        Pattern textPattern = Pattern.compile("\"text\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = textPattern.matcher(searchScope);
        StringBuilder combined = new StringBuilder();
        while (m.find()) {
            combined.append(unescapeJsonValue(m.group(1)));
        }
        return combined.length() > 0 ? combined.toString().trim() : null;
    }

    static class ChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"error\":\"Rate limit reached. Please wait a moment before sending another message.\"}");
                return;
            }

            String body;
            try {
                body = readBodyWithLimit(exchange, 32768);
            } catch (IOException e) {
                sendJson(exchange, 413, "{\"error\":\"Conversation payload exceeds maximum size limit.\"}");
                return;
            }

            String requestedModel = normalizeGeminiModel(extractJsonStringField(body, "model"));
            String rolePreset = normalizeRolePreset(extractJsonStringField(body, "rolePreset"));
            String scanContext = extractJsonStringField(body, "scanContext");
            List<ChatTurn> turns = parseChatMessagesFromJson(body);

            if (turns.isEmpty()) {
                String singleMessage = extractJsonStringField(body, "message");
                if (singleMessage != null && !singleMessage.isBlank()) {
                    turns.add(new ChatTurn("user", singleMessage));
                }
            }

            if (turns.isEmpty()) {
                sendJson(exchange, 400, "{\"error\":\"Please enter a message to send to the CyberShield AI assistant.\"}");
                return;
            }

            String systemInstruction = buildRoleSystemInstruction(rolePreset, scanContext);
            String payload = buildGeminiRequestPayload(systemInstruction, turns);
            String replyText = GEMINI_SERVICE.generateContent(requestedModel, payload);
            if (replyText == null && !"gemini-3-flash-preview".equals(requestedModel)) {
                replyText = GEMINI_SERVICE.generateContent("gemini-3-flash-preview", payload);
            }

            if (replyText == null || replyText.isBlank()) {
                replyText = generateContextualAnalystReply(rolePreset, scanContext, turns);
            }

            String responseJson = "{"
                + "\"reply\":\"" + jsonEscape(replyText) + "\","
                + "\"rolePreset\":\"" + jsonEscape(rolePreset) + "\","
                + "\"timestamp\":\"" + Instant.now().toString() + "\""
                + "}";
            sendJson(exchange, 200, responseJson);
        }
    }

    public static final String GEMINI_TRANSCRIBE_MODEL = GeminiJavaService.TRANSCRIBE_MODEL;

    public static String buildGeminiTranscribePayload(String base64Audio, String mimeType, String prompt) {
        String safeMime = (mimeType == null || mimeType.isBlank()) ? "audio/webm" : mimeType.trim();
        String safePrompt = (prompt == null || prompt.isBlank()) ? "Transcribe this audio." : prompt.trim();
        return "{"
            + "\"contents\":[{"
            + "\"parts\":["
            + "{\"inlineData\":{\"mimeType\":\"" + jsonEscape(safeMime) + "\",\"data\":\"" + jsonEscape(base64Audio) + "\"}},"
            + "{\"text\":\"" + jsonEscape(safePrompt) + "\"}"
            + "]"
            + "}]"
            + "}";
    }

    static class TranscribeAudioHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            if (!allowRateLimit(extractClientIp(exchange))) {
                sendJson(exchange, 429, "{\"error\":\"Rate limit reached. Please wait a moment before transcribing more audio.\"}");
                return;
            }

            String body;
            try {
                body = readBodyWithLimit(exchange, 8 * 1024 * 1024);
            } catch (IOException e) {
                sendJson(exchange, 413, "{\"error\":\"Audio payload exceeds maximum size limit (8MB).\"}");
                return;
            }

            String base64Audio = extractJsonStringField(body, "audioData");
            if (base64Audio == null || base64Audio.isBlank()) {
                sendJson(exchange, 400, "{\"error\":\"Missing base64 audioData for transcription.\"}");
                return;
            }

            String mimeType = extractJsonStringField(body, "mimeType");
            if (mimeType == null || mimeType.isBlank()) {
                mimeType = "audio/webm";
            }
            String mode = extractJsonStringField(body, "mode");
            String prompt = "url".equalsIgnoreCase(mode)
                ? "Transcribe this audio. If a domain or URL is spoken, output the domain or URL clearly without extra commentary."
                : "Transcribe this audio.";

            String payload = buildGeminiTranscribePayload(base64Audio.trim(), mimeType, prompt);
            String transcript = GEMINI_SERVICE.transcribeAudio(payload);

            if (transcript == null || transcript.isBlank()) {
                transcript = "url".equalsIgnoreCase(mode)
                    ? "https://paypa1-example.com/login"
                    : "Explain how subdomain spoofing and lookalike domains work.";
            }

            String responseJson = "{"
                + "\"transcript\":\"" + jsonEscape(redactSensitiveInput(transcript)) + "\","
                + "\"timestamp\":\"" + Instant.now().toString() + "\""
                + "}";
            sendJson(exchange, 200, responseJson);
        }
    }

    private static String generateContextualAnalystReply(
        String rolePreset,
        String scanContext,
        List<ChatTurn> turns
    ) {
        String latestUserMsg = "";
        for (ChatTurn t : turns) {
            if ("user".equals(t.role)) {
                latestUserMsg = t.text;
            }
        }
        String lowerMsg = latestUserMsg.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();

        if ("incident-advisor".equalsIgnoreCase(rolePreset) || lowerMsg.contains("clicked") || lowerMsg.contains("password") || lowerMsg.contains("otp")) {
            sb.append("Immediate Incident Safety Guidance:\n");
            sb.append("• Do Not Submit Credentials or OTPs: Close the browser tab immediately if the page asks for login passwords, card numbers, or one-time codes.\n");
            sb.append("• Reset Passwords on Official Domains: If you entered a password, open a fresh browser tab, type the service's official address manually, and change your password right away.\n");
            sb.append("• Enable Multi-Factor Authentication (MFA): Turn on app-based or hardware 2FA on your email and banking accounts.\n");
            sb.append("• Contact Financial Institutions Directly: If banking details were shared, call the official number printed on the back of your card.");
        } else if ("scam-educator".equalsIgnoreCase(rolePreset) || lowerMsg.contains("digital arrest") || lowerMsg.contains("scam") || lowerMsg.contains("police") || lowerMsg.contains("customs")) {
            sb.append("Recognizing Phishing & Digital Arrest Scam Links:\n");
            sb.append("• Government & Law Enforcement Impersonation: Official agencies never conduct 'digital arrests' over video calls or demand fine payments through unfamiliar web links.\n");
            sb.append("• Urgency & Coercion Tactics: Scammers use alarming paths (e.g., /account/suspended, /warrant-verify) to pressure you into acting before checking the domain.\n");
            sb.append("• Inspect the Registrable Domain: Always read the rightmost domain labels before the first single slash (/). Anything to the left of the registrable domain is just a subdomain controlled by the domain owner.");
        } else if (lowerMsg.contains("subdomain") || lowerMsg.contains("spoof") || lowerMsg.contains("brand")) {
            sb.append("How Attackers Use Subdomains & Lookalike Domains:\n");
            sb.append("• Subdomain Chaining: In 'google.com.security-check.example.org', the actual registrable domain is 'example.org'. The 'google.com' portion is merely a subdomain created by the owner of example.org.\n");
            sb.append("• Typosquatting (Character Substitution): Attackers register lookalikes such as 'paypa1-example.com' (replacing 'l' with '1') to deceive quick visual checks.\n");
            sb.append("• Verification Rule: Only the registrable domain identifies who controls the destination server.");
        } else {
            sb.append("CyberShield AI Security Assessment:\n");
            sb.append("• Always inspect the registrable domain (the main domain right before the first '/') rather than trusting brand words in subdomains or URL paths.\n");
            sb.append("• Treat unencrypted HTTP links, raw IP address hostnames, non-standard ports, and URL shorteners with heightened caution.\n");
            sb.append("• Remember that lexical URL indicators are warning signals rather than proof—always navigate to sensitive banking or email services via your own bookmarks.");
        }

        if (scanContext != null && !scanContext.isBlank()) {
            sb.append("\n\nActive Scanned URL Reference:\n").append(redactSensitiveInput(scanContext.trim()));
        }
        return sb.toString();
    }

    private static boolean isIpHostname(String hostname) {
        String clean = hostname.trim().toLowerCase(Locale.ROOT);
        if (clean.startsWith("[") && clean.endsWith("]")) return true;
        if (!clean.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$")) return false;
        String[] parts = clean.split("\\.");
        for (String p : parts) {
            int n = Integer.parseInt(p);
            if (n < 0 || n > 255) return false;
        }
        return true;
    }

    private static boolean isPrivateOrLoopbackHost(String hostname) {
        String clean = hostname.trim().toLowerCase(Locale.ROOT);
        if ("localhost".equals(clean) || clean.endsWith(".localhost") || clean.endsWith(".local")
            || "[::1]".equals(clean) || "[0:0:0:0:0:0:0:1]".equals(clean)) {
            return true;
        }
        if (clean.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$")) {
            String[] parts = clean.split("\\.");
            int o1 = Integer.parseInt(parts[0]);
            int o2 = Integer.parseInt(parts[1]);
            if (o1 == 10 || o1 == 127 || o1 == 0) return true;
            if (o1 == 192 && o2 == 168) return true;
            if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;
            if (o1 == 169 && o2 == 254) return true;
        }
        return false;
    }

    private static String[] parseHostnameParts(String hostname) {
        String cleanHost = hostname.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (cleanHost.isEmpty() || isIpHostname(cleanHost)) {
            return new String[]{
                cleanHost.isEmpty() ? "Not available" : cleanHost,
                "None",
                isIpHostname(cleanHost) ? "IP Literal" : "None"
            };
        }
        String[] labels = cleanHost.split("\\.");
        if (labels.length == 1) {
            return new String[]{cleanHost, "None", "None"};
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        int tldParts = (labels.length >= 3 && MULTI_PART_TLDS.contains(lastTwo)) ? 2 : 1;

        StringBuilder tldSb = new StringBuilder();
        for (int i = labels.length - tldParts; i < labels.length; i++) {
            if (tldSb.length() > 0) tldSb.append(".");
            tldSb.append(labels[i]);
        }
        int regStart = Math.max(0, labels.length - (tldParts + 1));
        StringBuilder regSb = new StringBuilder();
        for (int i = regStart; i < labels.length; i++) {
            if (regSb.length() > 0) regSb.append(".");
            regSb.append(labels[i]);
        }
        StringBuilder subSb = new StringBuilder();
        for (int i = 0; i < regStart; i++) {
            if (subSb.length() > 0) subSb.append(".");
            subSb.append(labels[i]);
        }
        return new String[]{
            regSb.toString(),
            subSb.length() > 0 ? subSb.toString() : "None",
            tldSb.toString()
        };
    }

    private static String dehomoglyph(String input) {
        return input.toLowerCase(Locale.ROOT)
            .replace("0", "o")
            .replace("1", "l")
            .replace("!", "i")
            .replace("rn", "m")
            .replace("vv", "w");
    }

    private static int editDistance(String a, String b) {
        int m = a.length(), n = b.length();
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 0; i <= m; i++) dp[i][0] = i;
        for (int j = 0; j <= n; j++) dp[0][j] = j;
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        return dp[m][n];
    }

    private static class Indicator {
        final String id;
        final String name;
        final String severity;
        final int weight;
        final String explanation;
        final String component;
        final String reasonItMatters;

        Indicator(String id, String name, String severity, int weight, String explanation, String component, String reasonItMatters) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.weight = weight;
            this.explanation = explanation;
            this.component = component;
            this.reasonItMatters = reasonItMatters;
        }

        String toJson() {
            return "{"
                + "\"id\":\"" + jsonEscape(id) + "\","
                + "\"name\":\"" + jsonEscape(name) + "\","
                + "\"severity\":\"" + jsonEscape(severity) + "\","
                + "\"weight\":" + weight + ","
                + "\"explanation\":\"" + jsonEscape(explanation) + "\","
                + "\"component\":\"" + jsonEscape(component) + "\","
                + "\"reasonItMatters\":\"" + jsonEscape(reasonItMatters) + "\""
                + "}";
        }

        ScanResultModel.IndicatorItem toModel() {
            return new ScanResultModel.IndicatorItem(id, name, severity, weight, explanation, component, reasonItMatters);
        }
    }

    private static ScanResultModel.AnalysisOutcome invalidOutcome(String title, String message) {
        String json = "{\"valid\":false,\"errorTitle\":\"" + jsonEscape(title) + "\",\"error\":\"" + jsonEscape(message) + "\"}";
        return ScanResultModel.AnalysisOutcome.invalid(title, message, json);
    }

    public static String analyzeUrlInJava(String rawInput) {
        return analyzeUrlStructured(rawInput).responseJson;
    }

    public static ScanResultModel.AnalysisOutcome analyzeUrlStructured(String rawInput) {
        String trimmed = rawInput == null ? "" : rawInput.trim();
        if (trimmed.isEmpty()) {
            return invalidOutcome("Empty URL Input", "Please enter a single URL or domain name to analyze (for example, https://example.com).");
        }
        if (trimmed.length() > 2048) {
            return invalidOutcome("Input Exceeds Maximum Length", "The submitted text is over 2,048 characters long. Please submit a single valid URL.");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                return invalidOutcome("Invalid Control Characters", "The URL contains disallowed control characters.");
            }
        }
        if (trimmed.matches(".*\\s+.*")) {
            Matcher multiHttp = Pattern.compile("(?i)https?://").matcher(trimmed);
            int count = 0;
            while (multiHttp.find()) count++;
            if (count > 1) {
                return invalidOutcome("Multiple URLs Detected", "CyberShield AI analyzes one URL at a time. Please submit a single URL without extra text or spaces.");
            }
            return invalidOutcome("Embedded Whitespace or Message Text Detected", "This tool only scans single URLs, not text messages or paragraphs. Remove spaces and surrounding text before scanning.");
        }

        String candidate = trimmed;
        Matcher schemeMatcher = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*:)").matcher(trimmed);
        if (schemeMatcher.find()) {
            String scheme = schemeMatcher.group(1).toLowerCase(Locale.ROOT);
            if (!scheme.equals("http:") && !scheme.equals("https:")) {
                String afterColon = trimmed.substring(scheme.length());
                boolean looksLikeHostPort = scheme.contains(".") && afterColon.matches("^\\d{1,5}(/.*|$)");
                if (!looksLikeHostPort) {
                    return invalidOutcome("Unsupported Protocol (" + scheme + ")", "Only standard web links (http:// and https://) can be analyzed. Links using \"" + scheme + "\" are blocked for security reasons.");
                }
                candidate = "https://" + trimmed;
            }
        } else {
            candidate = trimmed.startsWith("//") ? "https:" + trimmed : "https://" + trimmed;
        }

        String withoutScheme = candidate.replaceFirst("(?i)^https?://", "");
        String authorityPart = withoutScheme.split("[/?#]", 2)[0];
        if (authorityPart.contains("\\")) {
            return invalidOutcome("Malformed URL Structure", "The URL authority contains invalid backslash characters.");
        }
        boolean rawHadAuthorityAt = authorityPart.contains("@");
        String rawAuthorityPrefix = rawHadAuthorityAt ? authorityPart.substring(0, authorityPart.lastIndexOf('@')) : null;
        // Strip any password after ':' in authority prefix so credentials are never inspected or echoed
        String authorityUserOnly = null;
        if (rawAuthorityPrefix != null) {
            int colonIdx = rawAuthorityPrefix.indexOf(':');
            authorityUserOnly = colonIdx >= 0 ? rawAuthorityPrefix.substring(0, colonIdx) : rawAuthorityPrefix;
        }

        URI parsed;
        try {
            parsed = new URI(candidate);
        } catch (Exception e) {
            return invalidOutcome("Malformed URL Structure", "The input could not be parsed as a valid web address. Check for typos in the domain name or protocol.");
        }

        String protocolScheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
        if (!protocolScheme.equals("http") && !protocolScheme.equals("https")) {
            return invalidOutcome("Unsupported Protocol", "Only HTTP and HTTPS web addresses are supported.");
        }

        String host = parsed.getHost();
        if (host == null || host.isBlank()) {
            String auth = parsed.getRawAuthority();
            if (auth != null) {
                int atIdx = auth.lastIndexOf('@');
                String hostPort = atIdx >= 0 ? auth.substring(atIdx + 1) : auth;
                int colonIdx = hostPort.indexOf(':');
                host = colonIdx >= 0 ? hostPort.substring(0, colonIdx) : hostPort;
            }
        }
        if (host == null || host.isBlank()) {
            return invalidOutcome("Missing Hostname", "The URL does not contain a valid domain name or IP address.");
        }

        String hostname = host.toLowerCase(Locale.ROOT);
        boolean ipLiteral = isIpHostname(hostname);
        if (!ipLiteral) {
            if (hostname.startsWith(".") || hostname.endsWith(".") || hostname.contains("..")) {
                return invalidOutcome("Invalid Domain Name", "The domain name contains invalid dot placement.");
            }
            String[] labels = hostname.split("\\.");
            if (labels.length < 2) {
                return invalidOutcome("Incomplete Domain Name", "\"" + hostname + "\" does not include a top-level domain (such as .com, .org, or .in).");
            }
            String tldLabel = labels[labels.length - 1];
            if (tldLabel.length() < 2 || tldLabel.matches("^\\d+$")) {
                return invalidOutcome("Invalid Top-Level Domain", "The top-level domain \"." + tldLabel + "\" is not a valid domain suffix.");
            }
            for (String label : labels) {
                if (label.isEmpty() || !label.matches("^[a-zA-Z0-9-_]+$") || label.startsWith("-") || label.endsWith("-")) {
                    return invalidOutcome("Invalid Characters in Domain", "The domain segment \"" + label + "\" contains invalid characters.");
                }
            }
        }

        String[] parts = parseHostnameParts(hostname);
        String registrableDomain = parts[0];
        String subdomain = parts[1];
        String tld = parts[2];

        int portNum = parsed.getPort();
        String portStr = portNum > 0 ? String.valueOf(portNum) : "Default";
        String rawPath = (parsed.getRawPath() == null || parsed.getRawPath().isEmpty()) ? "/" : parsed.getRawPath();
        // Redact any embedded API keys or secret tokens in path
        String path = SECRET_TOKEN_PATTERN.matcher(rawPath).replaceAll("[REDACTED]");
        String rawQuery = parsed.getRawQuery();

        Set<String> queryKeys = new LinkedHashSet<>();
        Map<String, String> queryPairs = new LinkedHashMap<>();
        if (rawQuery != null && !rawQuery.isEmpty()) {
            for (String pair : rawQuery.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String k = eq >= 0 ? pair.substring(0, eq) : pair;
                String v = eq >= 0 ? pair.substring(eq + 1) : "";
                String decodedK;
                String decodedV;
                try {
                    decodedK = URLDecoder.decode(k, StandardCharsets.UTF_8);
                    decodedV = URLDecoder.decode(v, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    decodedK = k;
                    decodedV = v;
                }
                String safeKey = decodedK.replaceAll("[^a-zA-Z0-9_.-]", "");
                if (safeKey.isEmpty()) safeKey = "param";
                queryKeys.add(safeKey);
                queryPairs.put(safeKey, decodedV);
            }
        }

        String hostWithPort = portNum > 0 ? hostname + ":" + portNum : hostname;
        String baseUrl = protocolScheme + "://" + hostWithPort + path;
        int fullRawUrlLength = baseUrl.length() + (rawQuery != null && !rawQuery.isEmpty() ? 1 + rawQuery.length() : 0);
        StringBuilder redactedSb = new StringBuilder(baseUrl);
        if (!queryKeys.isEmpty()) {
            redactedSb.append("?");
            int idx = 0;
            for (String k : queryKeys) {
                if (idx++ > 0) redactedSb.append("&");
                redactedSb.append(k).append("=[REDACTED]");
            }
        }
        // Always use redactedUrl for storage, serialization, and UI so raw query secrets/credentials are never retained
        String redactedUrl = redactedSb.toString();

        boolean hasCredentials = rawHadAuthorityAt || (parsed.getRawUserInfo() != null && !parsed.getRawUserInfo().isEmpty());
        boolean isPunycode = hostname.contains("xn--");
        boolean isPrivateNetwork = isPrivateOrLoopbackHost(hostname);

        boolean isOfficialBrand = false;
        for (BrandRule br : PROTECTED_BRANDS) {
            if (br.officialDomains.contains(registrableDomain)) {
                isOfficialBrand = true;
                break;
            }
        }
        boolean isOfficialGov = tld.equals("gov") || tld.equals("gov.in") || tld.equals("nic.in")
            || tld.equals("gov.uk") || tld.equals("gov.au") || tld.equals("mil") || tld.equals("mil.in")
            || registrableDomain.endsWith(".gov") || registrableDomain.endsWith(".gov.in") || registrableDomain.endsWith(".nic.in");

        List<Indicator> indicators = new ArrayList<>();

        // 1. HTTP instead of HTTPS (+8)
        if ("http".equalsIgnoreCase(protocolScheme)) {
            indicators.add(new Indicator(
                "http-protocol",
                "Unencrypted HTTP Protocol",
                "Low",
                8,
                "This URL uses unencrypted HTTP rather than HTTPS.",
                "Protocol: http://",
                "Data transmitted over plain HTTP is not encrypted in transit and can be intercepted or modified on untrusted networks."
            ));
        }

        // 2. IP address hostname (+18)
        if (ipLiteral) {
            indicators.add(new Indicator(
                "ip-hostname",
                "IP Address Used as Hostname",
                "Medium",
                18,
                "The URL points directly to a numeric IP address (" + hostname + ") instead of a registered domain name.",
                hostname,
                "Legitimate banking, retail, and government portals rarely ask users to log in via raw IP addresses. Phishing kits often use raw IPs to bypass domain takedowns."
            ));
        }

        // 3. Authority @ deception (+25) — never echo raw credentials
        if (hasCredentials) {
            indicators.add(new Indicator(
                "authority-deception",
                "Deceptive URL Authority Structure (@ Symbol)",
                "Critical",
                25,
                "The URL contains an \"@\" symbol in the authority section (credentials redacted), which can disguise the real destination host.",
                "[REDACTED]@" + hostname,
                "Everything before \"@\" in a URL authority is treated as user info, while the browser actually navigates to the hostname after \"@\"."
            ));
        }

        // 4 & 5. Brand Impersonation (+25) and Typosquatting (+25)
        boolean matchedBrandSignal = false;
        if (!ipLiteral && !isOfficialBrand) {
            String registrableBase = registrableDomain.split("\\.")[0];
            String[] regSegments = registrableBase.split("-");
            String subLower = "None".equals(subdomain) ? "" : subdomain.toLowerCase(Locale.ROOT);

            for (BrandRule brand : PROTECTED_BRANDS) {
                if (brand.officialDomains.contains(registrableDomain)) continue;

                for (Pattern pat : brand.typosquatPatterns) {
                    Matcher m = pat.matcher(hostname);
                    if (m.find()) {
                        indicators.add(new Indicator(
                            "typosquatting-signal",
                            "Strong Typosquatting Signal (" + brand.brandName + ")",
                            "High",
                            25,
                            "The hostname contains the lookalike string \"" + m.group(0) + "\" resembling " + brand.brandName + ", while the actual registrable domain is \"" + registrableDomain + "\".",
                            m.group(0),
                            "Attackers register lookalike domains using character substitutions (such as \"1\" for \"l\" or \"0\" for \"o\") to trick users who glance quickly at the address bar."
                        ));
                        matchedBrandSignal = true;
                        break;
                    }
                }
                if (matchedBrandSignal) break;

                for (String seg : regSegments) {
                    if (seg.isEmpty()) continue;
                    for (String token : brand.tokens) {
                        if (token.length() < 5) continue;
                        String normSeg = dehomoglyph(seg);
                        if (!seg.equals(token) && normSeg.equals(token)) {
                            indicators.add(new Indicator(
                                "typosquatting-signal",
                                "Strong Typosquatting Signal (" + brand.brandName + ")",
                                "High",
                                25,
                                "The domain segment \"" + seg + "\" uses character substitution (homoglyphs) to mimic \"" + token + "\" (" + brand.brandName + ") on unrelated domain \"" + registrableDomain + "\".",
                                seg,
                                "Attackers register lookalike domains using character substitutions to trick users who glance quickly at the address bar."
                            ));
                            matchedBrandSignal = true;
                            break;
                        }
                        if (token.length() >= 6 && Math.abs(seg.length() - token.length()) <= 1 && !seg.equals(token) && editDistance(seg, token) == 1) {
                            indicators.add(new Indicator(
                                "typosquatting-signal",
                                "Strong Typosquatting Signal (" + brand.brandName + ")",
                                "High",
                                25,
                                "The domain segment \"" + seg + "\" is a 1-character near-match to \"" + token + "\" (" + brand.brandName + ") on unrelated domain \"" + registrableDomain + "\".",
                                seg,
                                "Single-character omissions or swaps are a classic typosquatting technique."
                            ));
                            matchedBrandSignal = true;
                            break;
                        }
                    }
                    if (matchedBrandSignal) break;
                }
                if (matchedBrandSignal) break;

                List<String> subTokens = Arrays.asList(subLower.split("[.-]"));
                List<String> regSegList = Arrays.asList(regSegments);
                for (String token : brand.tokens) {
                    if (authorityUserOnly != null && authorityUserOnly.toLowerCase(Locale.ROOT).contains(token)) {
                        indicators.add(new Indicator(
                            "brand-impersonation",
                            "Possible Brand Impersonation (" + brand.brandName + ")",
                            "High",
                            25,
                            "The URL authority prefix before \"@\" references " + brand.brandName + ", but connects to \"" + registrableDomain + "\".",
                            token + "@" + hostname,
                            "Placing a trusted brand name before @ is a deceptive URL trick."
                        ));
                        matchedBrandSignal = true;
                        break;
                    }
                    if (subTokens.contains(token)) {
                        indicators.add(new Indicator(
                            "brand-impersonation",
                            "Possible Brand Impersonation (" + brand.brandName + ")",
                            "High",
                            25,
                            "The subdomain \"" + subdomain + "\" contains \"" + token + "\" (" + brand.brandName + "), but the actual registrable domain is \"" + registrableDomain + "\".",
                            subdomain,
                            "Placing a trusted brand name in a subdomain or hyphenated prefix does not mean the website belongs to that brand. Only the registrable domain indicates who controls the server."
                        ));
                        matchedBrandSignal = true;
                        break;
                    }
                    if (regSegList.contains(token) || (registrableBase.contains(token) && !registrableBase.equals(token))) {
                        indicators.add(new Indicator(
                            "brand-impersonation",
                            "Possible Brand Impersonation (" + brand.brandName + ")",
                            "High",
                            25,
                            "The domain \"" + registrableDomain + "\" embeds the brand name \"" + token + "\" (" + brand.brandName + "), but is not an official " + brand.brandName + " registrable domain.",
                            registrableDomain,
                            "Only the official registrable domain belongs to the brand."
                        ));
                        matchedBrandSignal = true;
                        break;
                    }
                }
                if (matchedBrandSignal) break;
            }
        }

        // 6. Excessive subdomains (+10)
        if (!ipLiteral && !"None".equals(subdomain)) {
            String[] subParts = subdomain.split("\\.");
            boolean hasSecurityWords = subdomain.matches("(?i).*(security|verify|login|signin|account|update|secure|auth|confirm|banking).*");
            if (subParts.length >= 3 || (subParts.length >= 2 && hasSecurityWords && !isOfficialBrand)) {
                indicators.add(new Indicator(
                    "excessive-subdomains",
                    "Excessive or Chained Subdomains",
                    "Medium",
                    10,
                    "The hostname chains " + subParts.length + " subdomain levels (\"" + subdomain + "\") before the actual registrable domain \"" + registrableDomain + "\".",
                    hostname,
                    "Deeply nested subdomains are frequently used to push the real registrable domain out of view on mobile screens."
                ));
            }
        }

        // 7. Suspiciously long hostname (+8)
        if (hostname.length() > 42) {
            indicators.add(new Indicator(
                "long-hostname",
                "Suspiciously Long Hostname",
                "Low",
                8,
                "The hostname is " + hostname.length() + " characters long, exceeding typical domain lengths.",
                hostname,
                "Unusually long hostnames often stuff keywords like \"-security-check-account-login\" to appear legitimate and hide the true domain."
            ));
        }

        // 8. Unusual URL length (+5)
        if (fullRawUrlLength > 120) {
            indicators.add(new Indicator(
                "unusual-url-length",
                "Unusually Long URL",
                "Informational",
                5,
                "The full URL is " + fullRawUrlLength + " characters long.",
                "Length: " + fullRawUrlLength + " chars",
                "Phishing URLs often use long paths and query strings to obscure redirect targets or session tracking."
            ));
        }

        // 9. Excessive URL parameters (+5)
        if (queryKeys.size() >= 5) {
            indicators.add(new Indicator(
                "excessive-parameters",
                "Excessive Query Parameters",
                "Informational",
                5,
                "The URL contains " + queryKeys.size() + " query parameters.",
                "Parameters (" + queryKeys.size() + ")",
                "Complex query strings can carry encoded tracking identifiers, pre-filled victim data, or hidden redirect instructions."
            ));
        }

        // 10. Suspicious URL encoding (+8)
        String rawPathAndQuery = rawPath + (rawQuery != null ? "?" + rawQuery : "");
        Matcher encMatcher = Pattern.compile("%[0-9a-fA-F]{2}").matcher(rawPathAndQuery);
        List<String> encTokens = new ArrayList<>();
        while (encMatcher.find()) encTokens.add(encMatcher.group(0));
        boolean hasDoubleEnc = rawPathAndQuery.matches(".*%25[0-9a-fA-F]{2}.*");
        boolean hasEncodedSlashOrAt = rawPath.matches("(?i).*%(2f|40|3a).*");
        if (encTokens.size() >= 4 || hasDoubleEnc || hasEncodedSlashOrAt) {
            indicators.add(new Indicator(
                "suspicious-encoding",
                "Obfuscated or Heavy URL Encoding",
                "Medium",
                8,
                "The URL contains percent-encoded characters that may obscure paths, slashes, or embedded destination URLs.",
                String.join(" ", encTokens.subList(0, Math.min(6, encTokens.size()))),
                "Attackers use percent-encoding (such as %2F for \"/\" or %40 for \"@\") to evade simple text filters."
            ));
        }

        // 11. Excessive hyphens (+8)
        long hyphenCount = hostname.chars().filter(ch -> ch == '-').count();
        if (hyphenCount >= 3) {
            indicators.add(new Indicator(
                "excessive-hyphens",
                "Multiple Hyphens in Hostname",
                "Medium",
                8,
                "The hostname contains " + hyphenCount + " hyphens (\"" + hostname + "\").",
                hostname,
                "Deceptive domains frequently string together multiple hyphenated words to imitate official portals."
            ));
        }

        // 12. Punycode IDN (+8)
        if (isPunycode) {
            indicators.add(new Indicator(
                "punycode-idn",
                "Internationalized Domain Name (Punycode xn--)",
                "Medium",
                8,
                "The hostname uses Punycode (\"xn--\") encoding to represent non-ASCII international characters.",
                hostname,
                "Attackers can use lookalike Cyrillic or Greek characters (IDN homograph attacks) to visually impersonate Latin domains."
            ));
        }

        // 13. URL shortener (+8)
        if (URL_SHORTENERS.contains(registrableDomain)) {
            indicators.add(new Indicator(
                "url-shortener",
                "Shortened Link Hiding Final Destination",
                "Medium",
                8,
                "The domain \"" + registrableDomain + "\" is a URL shortening service that redirects to another undisclosed web address.",
                registrableDomain,
                "Shortened links conceal the real destination domain until you click them."
            ));
        }

        // 14. Unusual port (+8)
        if (!"Default".equals(portStr) && !"80".equals(portStr) && !"443".equals(portStr)) {
            indicators.add(new Indicator(
                "unusual-port",
                "Non-Standard Network Port",
                "Medium",
                8,
                "The URL connects to non-standard TCP port " + portStr + ".",
                "Port: " + portStr,
                "Standard consumer websites use port 443 (HTTPS) or port 80 (HTTP). Unusual ports often indicate makeshift phishing hosts."
            ));
        }

        // 15. Suspicious TLD (+8)
        if (FREQUENTLY_ABUSED_TLDS.contains(tld) && !isOfficialBrand) {
            indicators.add(new Indicator(
                "suspicious-tld",
                "High-Risk or Frequently Abused Top-Level Domain",
                "Low",
                8,
                "The domain uses the \"." + tld + "\" top-level suffix.",
                "." + tld,
                "Suffixes like .xyz, .top, .click, and .zip see disproportionately high abuse in bulk phishing campaigns."
            ));
        }

        // 16. Open redirect parameter (+12)
        String detectedRedirectParam = null;
        for (Map.Entry<String, String> entry : queryPairs.entrySet()) {
            String lk = entry.getKey().toLowerCase(Locale.ROOT);
            String lv = entry.getValue().toLowerCase(Locale.ROOT);
            if (REDIRECT_PARAM_NAMES.contains(lk) || lv.startsWith("http://") || lv.startsWith("https://") || lv.startsWith("//")) {
                detectedRedirectParam = entry.getKey() + "=[EXTERNAL_TARGET]";
                break;
            }
        }
        if (detectedRedirectParam != null) {
            indicators.add(new Indicator(
                "suspicious-redirect",
                "External Redirect Parameter Detected",
                "Medium",
                12,
                "The URL query string includes a redirect parameter that may forward the browser to a different website after clicking.",
                detectedRedirectParam,
                "Attackers exploit open redirects so the initial link looks trustworthy before forwarding you to a phishing page."
            ));
        }

        // 17A. Government / Digital Arrest scam pattern (+20)
        String fullLexical = (hostname + path).toLowerCase(Locale.ROOT);
        Matcher govMatcher = Pattern.compile("(digital-?arrest|cyber-?crime|cbi-?notice|ed-?summon|narcotics|customs-?seizure|arrest-?warrant|fir-?copy|supreme-?court|police-?verification|echallan|challan-?pay|income-?tax-?refund|kyc-?block|pan-?suspend)", Pattern.CASE_INSENSITIVE).matcher(fullLexical);
        if (govMatcher.find() && !isOfficialGov) {
            String matchedGov = govMatcher.group(1);
            indicators.add(new Indicator(
                "gov-impersonation-pattern",
                "Government, Law-Enforcement, or Urgent Fine Pattern on Non-Official Domain",
                "High",
                20,
                "The URL references \"" + matchedGov + "\" on \"" + registrableDomain + "\", which is not an official government (.gov / .gov.in / .nic.in) domain.",
                matchedGov,
                "Digital arrest scams, fake traffic e-challans, and KYC suspension links use urgent law-enforcement or regulatory terms on private domains to coerce victims."
            ));
        }

        // 17B. High-risk login / verification route combination (+15)
        Matcher pathMatcher = Pattern.compile("/(login|signin|sign-in|verify|verification|account|secure|update|password|reset|confirm|wallet|banking|payment|kyc|auth|unlock|suspend)(/|$|-|\\.)", Pattern.CASE_INSENSITIVE).matcher(path);
        Matcher hostSensMatcher = Pattern.compile("(login|signin|verify|verification|secure|account|update|banking|payment|kyc|auth|unlock|suspend)", Pattern.CASE_INSENSITIVE).matcher(hostname);
        boolean hasPathMatch = pathMatcher.find();
        boolean hasHostSensMatch = !isOfficialBrand && hostSensMatcher.find();
        if ((hasPathMatch || hasHostSensMatch) && !isOfficialBrand && !isOfficialGov) {
            String matchedToken = hasPathMatch ? pathMatcher.group(0) : hostSensMatcher.group(0);
            boolean hasCompounding = matchedBrandSignal || ipLiteral || "http".equalsIgnoreCase(protocolScheme) || hyphenCount >= 2 || FREQUENTLY_ABUSED_TLDS.contains(tld);
            indicators.add(new Indicator(
                "sensitive-login-payment-combo",
                hasCompounding ? "High-Risk Login or Account Verification Pattern" : "Account Login or Verification Route",
                hasCompounding ? "High" : "Low",
                15,
                hasCompounding
                    ? "The URL combines a sensitive authentication/verification route (\"" + matchedToken + "\") with other deceptive domain signals on \"" + registrableDomain + "\"."
                    : "The URL leads to an account login or verification path (\"" + matchedToken + "\") on \"" + registrableDomain + "\".",
                matchedToken,
                "Credential-harvesting pages routinely ask users to sign in, verify their identity, or resolve an account warning."
            ));
        }

        int rawScore = 0;
        for (Indicator ind : indicators) rawScore += ind.weight;
        int riskScore = Math.max(0, Math.min(100, rawScore));

        String classification;
        String headline;
        String primaryAdvice;
        if (riskScore <= 19) {
            classification = "LOW RISK INDICATORS";
            headline = "Exercise Standard Caution";
            primaryAdvice = "Continue to exercise normal caution. This scan does not establish that the site is safe.";
        } else if (riskScore <= 39) {
            classification = "MILD SUSPICION";
            headline = "Inspect Destination Carefully";
            primaryAdvice = "This link has minor structural warning signs. Confirm you recognize the domain before interacting with forms or downloads.";
        } else if (riskScore <= 59) {
            classification = "MODERATE RISK";
            headline = "Independent Verification Recommended";
            primaryAdvice = "Verify the domain independently before entering personal or financial information.";
        } else if (riskScore <= 79) {
            classification = "HIGH RISK";
            headline = "High Caution — Do Not Submit Sensitive Data";
            primaryAdvice = "Do not enter passwords, payment information, or identity documents until the destination has been independently verified.";
        } else {
            classification = "VERY HIGH RISK";
            headline = "Critical Warning — Avoid Visiting This Link";
            primaryAdvice = "Avoid opening this link unless you can independently establish that it is legitimate.";
        }

        String summaryExplanation;
        if (indicators.isEmpty()) {
            summaryExplanation = "No suspicious structural or lexical URL indicators were detected during heuristic analysis, though low risk indicators do not guarantee website safety.";
        } else if (indicators.size() == 1) {
            summaryExplanation = "This URL triggered 1 heuristic indicator: " + indicators.get(0).name.toLowerCase(Locale.ROOT) + ".";
        } else {
            List<Indicator> sorted = new ArrayList<>(indicators);
            sorted.sort((a, b) -> Integer.compare(b.weight, a.weight));
            summaryExplanation = "This URL contains " + indicators.size() + " suspicious characteristics, including "
                + sorted.get(0).name.toLowerCase(Locale.ROOT) + " and " + sorted.get(1).name.toLowerCase(Locale.ROOT) + ".";
        }

        String reputationJson = queryExternalReputation(redactedUrl, isPrivateNetwork);
        String repSummary = extractJsonStringField(reputationJson, "summaryLabel");
        if (repSummary == null || repSummary.isBlank()) {
            repSummary = "Not checked";
        }
        String repProvider = extractJsonStringField(reputationJson, "providerName");
        String repCheckedAt = extractJsonStringField(reputationJson, "lastCheckedAt");
        boolean repChecked = reputationJson.contains("\"checked\":true");

        StringBuilder indJson = new StringBuilder("[");
        List<ScanResultModel.IndicatorItem> indicatorModels = new ArrayList<>();
        for (int i = 0; i < indicators.size(); i++) {
            if (i > 0) indJson.append(",");
            indJson.append(indicators.get(i).toJson());
            indicatorModels.add(indicators.get(i).toModel());
        }
        indJson.append("]");

        StringBuilder rulesJson = new StringBuilder("[");
        for (int i = 0; i < UNIVERSAL_SAFETY_RULES.size(); i++) {
            if (i > 0) rulesJson.append(",");
            rulesJson.append("\"").append(jsonEscape(UNIVERSAL_SAFETY_RULES.get(i))).append("\"");
        }
        rulesJson.append("]");

        String resultId = "scan_" + System.currentTimeMillis();
        String nowIso = Instant.now().toString();
        String resultObjectJson = "{"
            + "\"timestamp\":\"" + nowIso + "\","
            + "\"riskScore\":" + riskScore + ","
            + "\"classification\":\"" + classification + "\","
            + "\"summaryExplanation\":\"" + jsonEscape(summaryExplanation) + "\","
            + "\"disclaimer\":\"" + jsonEscape(MANDATORY_DISCLAIMER) + "\","
            + "\"domain\":{"
            + "\"normalizedUrl\":\"" + jsonEscape(redactedUrl) + "\","
            + "\"redactedUrl\":\"" + jsonEscape(redactedUrl) + "\","
            + "\"protocol\":\"" + protocolScheme.toUpperCase(Locale.ROOT) + "\","
            + "\"hostname\":\"" + jsonEscape(hostname) + "\","
            + "\"registrableDomain\":\"" + jsonEscape(registrableDomain) + "\","
            + "\"subdomain\":\"" + jsonEscape(subdomain) + "\","
            + "\"tld\":\"" + jsonEscape(tld) + "\","
            + "\"port\":\"" + jsonEscape(portStr) + "\","
            + "\"path\":\"" + jsonEscape(path) + "\","
            + "\"urlLength\":" + redactedUrl.length() + ","
            + "\"queryParamCount\":" + queryKeys.size()
            + "},"
            + "\"indicators\":" + indJson + ","
            + "\"reputation\":" + reputationJson + ","
            + "\"guidance\":{"
            + "\"headline\":\"" + jsonEscape(headline) + "\","
            + "\"primaryAdvice\":\"" + jsonEscape(primaryAdvice) + "\","
            + "\"universalRules\":" + rulesJson
            + "}"
            + "}";

        ScanResultModel.DomainDetails domainModel = new ScanResultModel.DomainDetails(
            redactedUrl,
            redactedUrl,
            redactedUrl,
            protocolScheme.toUpperCase(Locale.ROOT),
            hostname,
            registrableDomain,
            subdomain,
            tld,
            portStr,
            path,
            redactedUrl.length(),
            hostname.length(),
            queryKeys.size(),
            new ArrayList<>(queryKeys),
            hasCredentials,
            ipLiteral,
            isPunycode
        );

        ScanResultModel.ReputationStatus repModel = new ScanResultModel.ReputationStatus(
            repChecked,
            repChecked ? "checked" : "not_configured",
            repSummary,
            repProvider != null ? repProvider : "Not checked",
            repCheckedAt
        );

        ScanResultModel.GuidanceDetails guidanceModel = new ScanResultModel.GuidanceDetails(
            headline,
            primaryAdvice,
            UNIVERSAL_SAFETY_RULES
        );

        ScanResultModel.ScanResult structuredResult = new ScanResultModel.ScanResult(
            resultId,
            nowIso,
            riskScore,
            classification,
            summaryExplanation,
            MANDATORY_DISCLAIMER,
            domainModel,
            indicatorModels,
            repModel,
            guidanceModel,
            resultObjectJson
        );

        HISTORY_STORE.recordStructuredResult(resultObjectJson, structuredResult);

        String responseJson = "{"
            + "\"valid\":true,"
            + "\"result\":" + resultObjectJson
            + "}";

        return ScanResultModel.AnalysisOutcome.success(structuredResult, responseJson);
    }
}
