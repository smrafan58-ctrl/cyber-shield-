import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * CyberShieldWebUi — Pure Java 17 Server-Side HTML5/CSS3/SVG View Renderer.
 * Renders the CyberShield AI web interface with a solid, warm, aesthetic design,
 * seamless client-side interactivity, voice input, responsive layout, and zero data leaks.
 */
public class CyberShieldWebUi {

    public static class ChatMessageView {
        public final String role;
        public final String text;
        public final String timestamp;
        public final String modelUsed;

        public ChatMessageView(String role, String text, String timestamp, String modelUsed) {
            this.role = role;
            this.text = text;
            this.timestamp = timestamp;
            this.modelUsed = modelUsed;
        }
    }

    private static class RiskTheme {
        final String textClass;
        final String strokeHex;
        final String barClass;
        final String borderClass;
        final String badgeBg;
        final String badgeBorder;

        RiskTheme(String textClass, String strokeHex, String barClass, String borderClass, String badgeBg, String badgeBorder) {
            this.textClass = textClass;
            this.strokeHex = strokeHex;
            this.barClass = barClass;
            this.borderClass = borderClass;
            this.badgeBg = badgeBg;
            this.badgeBorder = badgeBorder;
        }
    }

    private static RiskTheme getRiskTheme(String classification) {
        if ("LOW RISK INDICATORS".equalsIgnoreCase(classification)) {
            return new RiskTheme("tone-emerald", "#059669", "bar-emerald", "border-emerald", "#ECFDF5", "#A7F3D0");
        }
        if ("MILD SUSPICION".equalsIgnoreCase(classification)) {
            return new RiskTheme("tone-amber", "#D97706", "bar-amber", "border-amber", "#FFFBEB", "#FDE68A");
        }
        if ("MODERATE RISK".equalsIgnoreCase(classification)) {
            return new RiskTheme("tone-orange", "#EA580C", "bar-orange", "border-orange", "#FFF7ED", "#FDBA74");
        }
        if ("HIGH RISK".equalsIgnoreCase(classification)) {
            return new RiskTheme("tone-rose", "#E11D48", "bar-rose", "border-rose", "#FFF1F2", "#FDA4AF");
        }
        return new RiskTheme("tone-red", "#DC2626", "bar-red", "border-red", "#FEF2F2", "#FECACA");
    }

    private static String getSeverityClass(String severity) {
        if ("Critical".equalsIgnoreCase(severity)) return "tone-red fw-600";
        if ("High".equalsIgnoreCase(severity)) return "tone-rose fw-600";
        if ("Medium".equalsIgnoreCase(severity)) return "tone-amber fw-600";
        if ("Low".equalsIgnoreCase(severity)) return "tone-terracotta fw-600";
        return "tone-muted fw-500";
    }

    public static String htmlEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\'': sb.append("&#39;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String urlEncode(String s) {
        if (s == null) return "";
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public static String renderScannerPage(
        String urlInput,
        String errorTitle,
        String errorMessage,
        List<ScanResultModel.ScanResult> history,
        boolean chatOpen,
        String chatRole,
        String chatModel,
        List<ChatMessageView> chatMessages,
        String chatError,
        String mandatoryDisclaimer
    ) {
        StringBuilder sb = new StringBuilder(32768);
        appendDocumentStart(sb, "CyberShield AI — URL Threat Detection & Phishing Risk Analyzer");
        appendNavbar(sb, false, null, chatOpen);

        sb.append("<main class=\"main-content\">\n");
        sb.append("  <div class=\"container-narrow stack-lg\">\n");

        // Unified Editorial Hero + URL Inspection Console
        sb.append("    <section class=\"card-editorial overflow-hidden hero-card\" aria-label=\"URL Inspection Console\">\n");
        sb.append("      <div class=\"hero-masthead\">\n");
        sb.append("        <span class=\"hero-badge\">Real-Time Threat Intelligence · Zero Unwanted Data</span>\n");
        sb.append("        <h1 class=\"hero-title\">Is This Link Safe Before You Click?</h1>\n");
        sb.append("        <p class=\"hero-subtitle\">Instantly scan suspicious links for deceptive brand impersonation, typosquatting homoglyphs, lookalike domains, unencrypted routes, and phishing lures.</p>\n");
        sb.append("      </div>\n");

        sb.append("      <div class=\"console-body\">\n");
        sb.append("        <form id=\"scan-form\" action=\"/scan\" method=\"POST\" novalidate>\n");
        if (chatOpen) {
            sb.append("          <input type=\"hidden\" name=\"chat\" value=\"open\" />\n");
        }
        String safeInput = CyberShieldServer.redactSensitiveInput(urlInput == null ? "" : urlInput.trim());
        sb.append("          <div class=\"label-row\">\n");
        sb.append("            <label for=\"url-scanner-input\" class=\"input-label\">Enter or paste a single web address to analyze</label>\n");
        sb.append("            <span class=\"meta-mono\">")
          .append(safeInput.isEmpty() ? "HTTP / HTTPS" : safeInput.length() + " chars")
          .append("</span>\n");
        sb.append("          </div>\n");

        sb.append("          <div class=\"scanner-bar\">\n");
        sb.append("            <div class=\"input-wrapper\">\n");
        sb.append("              <span class=\"input-icon\" aria-hidden=\"true\">\n");
        sb.append("                <svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M2 12h20\"/><path d=\"M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z\"/></svg>\n");
        sb.append("              </span>\n");
        sb.append("              <input id=\"url-scanner-input\" name=\"url\" type=\"text\" inputmode=\"url\" autocomplete=\"off\" autocorrect=\"off\" autocapitalize=\"none\" spellcheck=\"false\" value=\"")
          .append(htmlEscape(safeInput))
          .append("\" placeholder=\"https://example.com/login/verify\" aria-invalid=\"")
          .append(errorTitle != null ? "true" : "false")
          .append("\" aria-describedby=\"url-privacy-notice\" class=\"url-input\" />\n");
        sb.append("              <button type=\"button\" id=\"btn-voice-input\" class=\"btn-voice-icon\" title=\"Dictate URL with microphone\" aria-label=\"Dictate URL with microphone\">\n");
        sb.append("                <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z\"/><path d=\"M19 10v2a7 7 0 0 1-14 0v-2\"/><line x1=\"12\" y1=\"19\" x2=\"12\" y2=\"23\"/><line x1=\"8\" y1=\"23\" x2=\"16\" y2=\"23\"/></svg>\n");
        sb.append("              </button>\n");
        sb.append("            </div>\n");

        sb.append("            <div class=\"button-group\">\n");
        sb.append("              <button type=\"submit\" id=\"btn-submit-scan\" class=\"btn-primary\">\n");
        sb.append("                <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\" aria-hidden=\"true\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><path d=\"m21 21-4.3-4.3\"/></svg>\n");
        sb.append("                <span>Scan URL</span>\n");
        sb.append("              </button>\n");
        sb.append("              <a href=\"/\" class=\"btn-secondary\" aria-label=\"Clear URL input and reset results\">Clear</a>\n");
        sb.append("            </div>\n");
        sb.append("          </div>\n");

        if (errorTitle != null && !errorTitle.isBlank()) {
            sb.append("          <div role=\"alert\" class=\"alert-error\">\n");
            sb.append("            <div class=\"alert-title\">").append(htmlEscape(errorTitle)).append("</div>\n");
            sb.append("            <p class=\"alert-desc\">").append(htmlEscape(errorMessage != null ? errorMessage : "")).append("</p>\n");
            sb.append("          </div>\n");
        }

        sb.append("          <div id=\"url-privacy-notice\" class=\"privacy-strip\">\n");
        sb.append("            <span>Safe static inspection: Submitted URLs are never opened, fetched, or executed in your browser.</span>\n");
        sb.append("            <span class=\"meta-mono\">Query values &amp; credentials automatically redacted</span>\n");
        sb.append("          </div>\n");
        sb.append("        </form>\n");

        // Diagnostic Verification Presets
        sb.append("        <div id=\"diagnostic-presets\" class=\"presets-block\">\n");
        sb.append("          <div class=\"label-row\">\n");
        sb.append("            <span class=\"section-subhead\">Diagnostic Verification Presets</span>\n");
        sb.append("            <span class=\"meta-quiet\">Click a test URL to evaluate heuristic detection</span>\n");
        sb.append("          </div>\n");
        sb.append("          <div class=\"presets-grid\">\n");
        List<ScanResultModel.ExamplePreset> presets = ScanResultModel.DIAGNOSTIC_PRESETS;
        for (int i = 0; i < presets.size(); i++) {
            ScanResultModel.ExamplePreset preset = presets.get(i);
            sb.append("            <form action=\"/scan\" method=\"POST\" class=\"preset-form\">\n");
            sb.append("              <input type=\"hidden\" name=\"url\" value=\"").append(htmlEscape(preset.url)).append("\" />\n");
            if (chatOpen) {
                sb.append("              <input type=\"hidden\" name=\"chat\" value=\"open\" />\n");
            }
            sb.append("              <button type=\"submit\" class=\"preset-card\">\n");
            sb.append("                <div class=\"preset-card-top\">\n");
            sb.append("                  <span class=\"preset-title\">0").append(i + 1).append(". ").append(htmlEscape(preset.label)).append("</span>\n");
            sb.append("                  <span class=\"preset-arrow\" aria-hidden=\"true\">↗</span>\n");
            sb.append("                </div>\n");
            sb.append("                <div class=\"preset-url\">").append(htmlEscape(preset.url)).append("</div>\n");
            sb.append("              </button>\n");
            sb.append("            </form>\n");
        }
        sb.append("          </div>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("    </section>\n");

        // Recent Scan History (Last 5 Analyzed URLs)
        sb.append("    <section id=\"recent-history\" data-testid=\"recent-scan-history\" aria-labelledby=\"recent-scan-history-heading\" class=\"card-editorial section-pad\">\n");
        sb.append("      <div class=\"section-header\">\n");
        sb.append("        <div>\n");
        sb.append("          <h2 id=\"recent-scan-history-heading\" class=\"section-title\">Recent Scan History</h2>\n");
        sb.append("          <p class=\"meta-quiet\">Last 5 analyzed URLs in this session</p>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"header-actions\">\n");
        int histCount = history == null ? 0 : history.size();
        sb.append("          <span class=\"meta-mono\">").append(histCount).append(" / 5 saved</span>\n");
        if (histCount > 0) {
            sb.append("          <form action=\"/clear-history\" method=\"POST\" class=\"inline-form\">\n");
            sb.append("            <button type=\"submit\" class=\"btn-clear-history\">Clear History</button>\n");
            sb.append("          </form>\n");
        }
        sb.append("        </div>\n");
        sb.append("      </div>\n");

        if (histCount == 0) {
            sb.append("      <div class=\"empty-state\">\n");
            sb.append("        <p class=\"empty-title\">No URLs analyzed in this session yet</p>\n");
            sb.append("        <p class=\"empty-desc\">Scan any link above or select one of the diagnostic presets to record your last 5 analyzed URLs and risk scores here.</p>\n");
            sb.append("      </div>\n");
        } else {
            sb.append("      <ul class=\"history-list\">\n");
            for (int i = 0; i < history.size(); i++) {
                ScanResultModel.ScanResult item = history.get(i);
                RiskTheme theme = getRiskTheme(item.classification);
                double ringRadius = 15.0;
                double ringCirc = 2.0 * Math.PI * ringRadius;
                double ringOffset = ringCirc - (item.riskScore / 100.0) * ringCirc;

                sb.append("        <li data-testid=\"recent-scan-history-item\" class=\"history-row\">\n");
                sb.append("          <form action=\"/scan\" method=\"POST\" class=\"history-item-form\">\n");
                sb.append("            <input type=\"hidden\" name=\"url\" value=\"").append(htmlEscape(item.domain.redactedUrl)).append("\" />\n");
                if (chatOpen) {
                    sb.append("            <input type=\"hidden\" name=\"chat\" value=\"open\" />\n");
                }
                sb.append("            <button type=\"submit\" class=\"history-item-btn\">\n");
                sb.append("              <div class=\"history-left\">\n");
                sb.append("                <span class=\"history-idx\">0").append(i + 1).append(".</span>\n");
                sb.append("                <div class=\"mini-gauge\">\n");
                sb.append("                  <svg width=\"40\" height=\"40\" viewBox=\"0 0 38 38\" class=\"gauge-svg\" aria-hidden=\"true\">\n");
                sb.append("                    <circle cx=\"19\" cy=\"19\" r=\"15\" stroke=\"#EAE4D9\" stroke-width=\"3.5\" fill=\"transparent\" />\n");
                sb.append(String.format(Locale.US,
                    "                    <circle cx=\"19\" cy=\"19\" r=\"15\" stroke=\"%s\" stroke-width=\"3.5\" stroke-dasharray=\"%.2f\" stroke-dashoffset=\"%.2f\" stroke-linecap=\"round\" fill=\"transparent\" />\n",
                    theme.strokeHex, ringCirc, ringOffset));
                sb.append("                  </svg>\n");
                sb.append("                  <span class=\"mini-gauge-score ").append(theme.textClass).append("\">").append(item.riskScore).append("</span>\n");
                sb.append("                </div>\n");
                sb.append("                <div class=\"history-domain-meta\">\n");
                sb.append("                  <div class=\"history-host-line\">\n");
                sb.append("                    <span class=\"history-hostname\">").append(htmlEscape(item.domain.hostname)).append("</span>\n");
                sb.append("                    <span class=\"sep\" aria-hidden=\"true\">·</span>\n");
                sb.append("                    <span class=\"meta-mono\">").append(htmlEscape(item.domain.protocol)).append("</span>\n");
                sb.append("                    <span class=\"sep\" aria-hidden=\"true\">·</span>\n");
                sb.append("                    <span class=\"meta-mono\">").append(item.indicators.size()).append(item.indicators.size() == 1 ? " finding" : " findings").append("</span>\n");
                sb.append("                  </div>\n");
                sb.append("                  <div class=\"history-url\">").append(htmlEscape(item.domain.redactedUrl)).append("</div>\n");
                sb.append("                </div>\n");
                sb.append("              </div>\n");

                sb.append("              <div class=\"history-right\">\n");
                sb.append("                <div class=\"history-score-col\">\n");
                sb.append("                  <div class=\"history-score-text\">\n");
                sb.append("                    <span class=\"fw-700 ").append(theme.textClass).append("\">").append(item.riskScore).append("</span>\n");
                sb.append("                    <span class=\"meta-mono\">/ 100</span>\n");
                sb.append("                    <span class=\"sep\" aria-hidden=\"true\">·</span>\n");
                sb.append("                    <span class=\"fw-600 ").append(theme.textClass).append("\">").append(htmlEscape(item.classification)).append("</span>\n");
                sb.append("                  </div>\n");
                sb.append("                  <div class=\"mini-bar-track\">\n");
                sb.append("                    <div class=\"mini-bar-fill ").append(theme.barClass).append("\" style=\"width:").append(Math.max(4, item.riskScore)).append("%\"></div>\n");
                sb.append("                  </div>\n");
                sb.append("                </div>\n");
                sb.append("                <span class=\"view-report-cta\">View Report ↗</span>\n");
                sb.append("              </div>\n");
                sb.append("            </button>\n");
                sb.append("          </form>\n");
                sb.append("        </li>\n");
            }
            sb.append("      </ul>\n");
        }
        sb.append("    </section>\n");

        // Universal Safety Rules Reference Card
        sb.append("    <section id=\"safety-rules\" class=\"card-editorial section-pad\" aria-labelledby=\"safety-rules-heading\">\n");
        sb.append("      <div class=\"section-header\">\n");
        sb.append("        <div>\n");
        sb.append("          <h2 id=\"safety-rules-heading\" class=\"section-title\">Universal URL Verification Rules</h2>\n");
        sb.append("          <p class=\"meta-quiet\">Core defensive habits against phishing, brand spoofing, and coercive scam links</p>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"rules-grid\">\n");
        sb.append("        <div class=\"rule-item\"><span class=\"rule-num\">01.</span><div><strong>Verify the Registrable Domain</strong><p>Always read the rightmost domain labels right before the first single slash (/). Subdomains to the left can be created freely by an attacker.</p></div></div>\n");
        sb.append("        <div class=\"rule-item\"><span class=\"rule-num\">02.</span><div><strong>Never Enter Credentials on Unverified Links</strong><p>Do not submit passwords, OTPs, or banking details on pages reached through unsolicited SMS, email, or messaging links.</p></div></div>\n");
        sb.append("        <div class=\"rule-item\"><span class=\"rule-num\">03.</span><div><strong>Watch for Lookalike Substitutions</strong><p>Check carefully for homoglyphs like 'paypa1' or 'g00gle' and hyphenated prefixes designed to imitate official portals.</p></div></div>\n");
        sb.append("        <div class=\"rule-item\"><span class=\"rule-num\">04.</span><div><strong>Reject Coercive Fine or Arrest Claims</strong><p>Government agencies and courts never demand immediate fine transfers or conduct 'digital arrests' via web links.</p></div></div>\n");
        sb.append("      </div>\n");
        sb.append("    </section>\n");

        sb.append("  </div>\n");
        sb.append("</main>\n");

        appendChatAdvisor(sb, chatOpen, chatRole, chatMessages, chatError, null);
        appendFooter(sb, mandatoryDisclaimer);
        appendDocumentEnd(sb);
        return sb.toString();
    }

    public static String renderResultsPage(
        ScanResultModel.ScanResult result,
        boolean chatOpen,
        String chatRole,
        String chatModel,
        List<ChatMessageView> chatMessages,
        String chatError
    ) {
        StringBuilder sb = new StringBuilder(36000);
        RiskTheme theme = getRiskTheme(result.classification);
        double radius = 58.0;
        double circumference = 2.0 * Math.PI * radius;
        double strokeDashoffset = circumference - (result.riskScore / 100.0) * circumference;

        appendDocumentStart(sb, "Scan Report: " + result.domain.hostname + " (" + result.riskScore + "/100) — CyberShield AI");
        appendNavbar(sb, true, result.domain.redactedUrl, chatOpen);

        sb.append("<main class=\"main-content\">\n");
        sb.append("  <div class=\"container-wide stack-md\">\n");

        // Top Navigation Back to Scanner
        sb.append("    <div class=\"back-row\">\n");
        sb.append("      <a href=\"/\" class=\"back-link\">← Back to URL Scanner</a>\n");
        sb.append("      <div class=\"back-actions\">\n");
        sb.append("        <button type=\"button\" id=\"btn-copy-url\" class=\"btn-copy\" data-copy=\"").append(htmlEscape(result.domain.redactedUrl)).append("\">\n");
        sb.append("          <svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"/><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"/></svg>\n");
        sb.append("          <span>Copy Sanitized Link</span>\n");
        sb.append("        </button>\n");
        sb.append("        <div class=\"meta-mono\">Host: ").append(htmlEscape(result.domain.hostname)).append("</div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");

        // Deconstructed URL Anatomy Ribbon
        sb.append("    <section aria-label=\"Parsed URL Structural Anatomy\" class=\"card-editorial overflow-hidden\">\n");
        sb.append("      <div class=\"anatomy-header\">\n");
        sb.append("        <span class=\"fw-600\">Deconstructed URL Anatomy</span>\n");
        sb.append("        <span class=\"meta-mono truncate-text\" title=\"").append(htmlEscape(result.domain.redactedUrl)).append("\">").append(htmlEscape(result.domain.redactedUrl)).append("</span>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"anatomy-grid\">\n");
        sb.append("        <div class=\"anatomy-cell\">\n");
        sb.append("          <div class=\"anatomy-label\">Protocol</div>\n");
        sb.append("          <div class=\"anatomy-val ").append("HTTP".equals(result.domain.protocol) ? "tone-amber" : "tone-emerald").append("\">")
          .append(htmlEscape(result.domain.protocol)).append("</div>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"anatomy-cell\">\n");
        sb.append("          <div class=\"anatomy-label\">Subdomain</div>\n");
        sb.append("          <div class=\"anatomy-val\">").append(htmlEscape(result.domain.subdomain)).append("</div>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"anatomy-cell anatomy-highlight\">\n");
        sb.append("          <div class=\"anatomy-label tone-terracotta\">Registrable Domain</div>\n");
        sb.append("          <div class=\"anatomy-val tone-terracotta fw-700\">").append(htmlEscape(result.domain.registrableDomain)).append("</div>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"anatomy-cell\">\n");
        sb.append("          <div class=\"anatomy-label\">Port</div>\n");
        sb.append("          <div class=\"anatomy-val\">").append(htmlEscape(result.domain.port)).append("</div>\n");
        sb.append("        </div>\n");
        sb.append("        <div class=\"anatomy-cell\">\n");
        sb.append("          <div class=\"anatomy-label\">Path</div>\n");
        sb.append("          <div class=\"anatomy-val\">").append(htmlEscape(result.domain.path)).append("</div>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");
        sb.append("    </section>\n");

        // Top Row: A. Heuristic Threat Assessment + D. Recommended Safety Actions
        sb.append("    <div class=\"dashboard-grid-12\">\n");

        // A. Risk Score Card (7 cols)
        sb.append("      <section aria-labelledby=\"risk-score-heading\" class=\"col-span-7 card-editorial section-pad flex-col-between ").append(theme.borderClass).append("\">\n");
        sb.append("        <div>\n");
        sb.append("          <div class=\"section-header\">\n");
        sb.append("            <div>\n");
        sb.append("              <h2 id=\"risk-score-heading\" class=\"section-title\">Heuristic Threat Assessment</h2>\n");
        sb.append("              <p class=\"meta-mono\">").append(htmlEscape(result.domain.hostname)).append("</p>\n");
        sb.append("            </div>\n");
        sb.append("            <span class=\"badge-finding\">").append(result.indicators.size()).append(result.indicators.size() == 1 ? " Finding" : " Findings").append("</span>\n");
        sb.append("          </div>\n");

        sb.append("          <div class=\"score-hero-row\">\n");
        sb.append("            <div class=\"gauge-container\">\n");
        sb.append("              <svg width=\"160\" height=\"160\" viewBox=\"0 0 140 140\" class=\"gauge-svg\" aria-hidden=\"true\">\n");
        sb.append("                <circle cx=\"70\" cy=\"70\" r=\"66\" stroke=\"#E5DFD5\" stroke-width=\"1\" stroke-dasharray=\"3 3\" fill=\"transparent\" />\n");
        sb.append("                <circle cx=\"70\" cy=\"70\" r=\"58\" stroke=\"#EAE4D9\" stroke-width=\"10\" fill=\"transparent\" />\n");
        sb.append(String.format(Locale.US,
            "                <circle cx=\"70\" cy=\"70\" r=\"58\" stroke=\"%s\" stroke-width=\"10\" stroke-dasharray=\"%.2f\" stroke-dashoffset=\"%.2f\" stroke-linecap=\"round\" fill=\"transparent\" />\n",
            theme.strokeHex, circumference, strokeDashoffset));
        sb.append("              </svg>\n");
        sb.append("              <div class=\"gauge-center\">\n");
        sb.append("                <span data-testid=\"risk-score-value\" class=\"gauge-big-num ").append(theme.textClass).append("\">").append(result.riskScore).append("</span>\n");
        sb.append("                <span class=\"meta-mono\">/ 100</span>\n");
        sb.append("              </div>\n");
        sb.append("            </div>\n");

        sb.append("            <div class=\"score-summary-col\">\n");
        sb.append("              <div class=\"classification-line\">\n");
        sb.append("                <span data-testid=\"risk-classification-label\" class=\"classification-pill\" style=\"background:").append(theme.badgeBg).append(";border:1px solid ").append(theme.badgeBorder).append(";color:").append(theme.strokeHex).append("\">")
          .append(htmlEscape(result.classification)).append("</span>\n");
        sb.append("              </div>\n");
        sb.append("              <p class=\"summary-prose\">").append(htmlEscape(result.summaryExplanation)).append("</p>\n");

        sb.append("              <div class=\"linear-meter-block\">\n");
        sb.append("                <div class=\"label-row meta-mono\">\n");
        sb.append("                  <span>Composite Risk Score</span>\n");
        sb.append("                  <span>").append(result.riskScore).append(" / 100</span>\n");
        sb.append("                </div>\n");
        sb.append("                <div class=\"meter-track\">\n");
        sb.append("                  <div class=\"meter-fill ").append(theme.barClass).append("\" style=\"width:").append(Math.max(3, result.riskScore)).append("%\"></div>\n");
        sb.append("                </div>\n");
        sb.append("                <div class=\"meter-ticks meta-mono\">\n");
        sb.append("                  <span>0 Low</span><span>20 Mild</span><span>40 Mod</span><span>60 High</span><span>80+ Critical</span>\n");
        sb.append("                </div>\n");
        sb.append("              </div>\n");
        sb.append("            </div>\n");
        sb.append("          </div>\n");
        sb.append("        </div>\n");

        sb.append("        <div class=\"disclaimer-box\">\n");
        sb.append("          <p>").append(htmlEscape(result.disclaimer)).append("</p>\n");
        sb.append("        </div>\n");
        sb.append("      </section>\n");

        // D. Recommended Safety Actions Card (5 cols)
        sb.append("      <section aria-labelledby=\"recommended-actions-heading\" class=\"col-span-5 card-editorial section-pad flex-col-between\">\n");
        sb.append("        <div>\n");
        sb.append("          <div class=\"section-header\">\n");
        sb.append("            <div>\n");
        sb.append("              <h2 id=\"recommended-actions-heading\" class=\"section-title\">Recommended Safety Actions</h2>\n");
        sb.append("              <p class=\"meta-quiet\">").append(htmlEscape(result.guidance.headline)).append("</p>\n");
        sb.append("            </div>\n");
        sb.append("          </div>\n");
        sb.append("          <div class=\"primary-advice ").append(theme.textClass).append("\">\n");
        sb.append("            ").append(htmlEscape(result.guidance.primaryAdvice)).append("\n");
        sb.append("          </div>\n");
        sb.append("          <ul class=\"guidance-list\">\n");
        for (int i = 0; i < result.guidance.universalRules.size(); i++) {
            sb.append("            <li><span class=\"rule-num\">0").append(i + 1).append(".</span><span>")
              .append(htmlEscape(result.guidance.universalRules.get(i))).append("</span></li>\n");
        }
        sb.append("          </ul>\n");
        sb.append("        </div>\n");

        String encodedUrl = urlEncode(result.domain.redactedUrl);
        sb.append("        <div class=\"action-bar-footer\">\n");
        sb.append("          <a href=\"/\" class=\"btn-primary\">Scan Another URL</a>\n");
        sb.append("          <a href=\"/export?url=").append(encodedUrl).append("&amp;format=txt\" class=\"btn-secondary\" download>Download Report as TXT</a>\n");
        sb.append("          <a href=\"/export?url=").append(encodedUrl).append("&amp;format=json\" class=\"btn-secondary\" download>Download JSON</a>\n");
        sb.append("        </div>\n");
        sb.append("      </section>\n");
        sb.append("    </div>\n");

        // Bottom Row: B. Detected URL Indicators (7 cols) + C. Extracted Domain Details (5 cols)
        sb.append("    <div class=\"dashboard-grid-12\">\n");

        // B. Detected URL Indicators
        sb.append("      <section aria-labelledby=\"detected-indicators-heading\" class=\"col-span-7 card-editorial section-pad\">\n");
        sb.append("        <div class=\"section-header\">\n");
        sb.append("          <div>\n");
        sb.append("            <h2 id=\"detected-indicators-heading\" class=\"section-title\">Detected URL Indicators</h2>\n");
        sb.append("            <p class=\"meta-quiet\">Security signals identified in this URL</p>\n");
        sb.append("          </div>\n");
        sb.append("          <span class=\"badge-finding\">").append(result.indicators.size()).append(" Triggered</span>\n");
        sb.append("        </div>\n");

        if (result.indicators.isEmpty()) {
            sb.append("        <div class=\"empty-state\">\n");
            sb.append("          <h3 class=\"empty-title tone-emerald\">No Suspicious URL Heuristics Triggered</h3>\n");
            sb.append("          <p class=\"empty-desc\">This URL uses HTTPS, a standard domain structure, and did not match known brand impersonation or deceptive path patterns. Continue to verify the sender before logging in.</p>\n");
            sb.append("        </div>\n");
        } else {
            sb.append("        <div class=\"indicator-list\">\n");
            for (int i = 0; i < result.indicators.size(); i++) {
                ScanResultModel.IndicatorItem ind = result.indicators.get(i);
                sb.append("          <article class=\"indicator-article\">\n");
                sb.append("            <div class=\"indicator-top\">\n");
                sb.append("              <h3 class=\"indicator-title\"><span class=\"rule-num\">0").append(i + 1).append(".</span> ")
                  .append(htmlEscape(ind.name)).append("</h3>\n");
                sb.append("              <div class=\"meta-mono\">\n");
                sb.append("                <span class=\"").append(getSeverityClass(ind.severity)).append("\">Severity: ").append(htmlEscape(ind.severity)).append("</span>\n");
                sb.append("                <span class=\"sep\" aria-hidden=\"true\">·</span>\n");
                sb.append("                <span class=\"fw-700\">+").append(ind.weight).append(" pts</span>\n");
                sb.append("              </div>\n");
                sb.append("            </div>\n");
                sb.append("            <p class=\"indicator-exp\">").append(htmlEscape(ind.explanation)).append("</p>\n");
                sb.append("            <div class=\"indicator-comp\">Matched Component: <code>").append(htmlEscape(ind.component)).append("</code></div>\n");
                sb.append("            <p class=\"indicator-why\"><strong>Why this matters:</strong> ").append(htmlEscape(ind.reasonItMatters)).append("</p>\n");
                sb.append("          </article>\n");
            }
            sb.append("        </div>\n");
        }
        sb.append("      </section>\n");

        // C. Extracted Domain Details — Only verified URL anatomy fields, zero placeholder clutter
        sb.append("      <section aria-labelledby=\"domain-info-heading\" class=\"col-span-5 card-editorial section-pad\">\n");
        sb.append("        <div class=\"section-header\">\n");
        sb.append("          <h2 id=\"domain-info-heading\" class=\"section-title\">Extracted Domain Details</h2>\n");
        sb.append("          <span class=\"meta-quiet\">Verified URL Components</span>\n");
        sb.append("        </div>\n");
        sb.append("        <dl class=\"domain-dl\">\n");
        appendDlRow(sb, "Hostname", result.domain.hostname, false);
        appendDlRow(sb, "Registrable Domain", result.domain.registrableDomain, true);
        appendDlRow(sb, "Subdomain", result.domain.subdomain, false);
        String tldDisplay = ("IP Literal".equals(result.domain.tld) || "None".equals(result.domain.tld))
            ? result.domain.tld
            : "." + result.domain.tld;
        appendDlRow(sb, "Top-Level Domain (TLD)", tldDisplay, false);
        appendDlRow(sb, "Protocol", result.domain.protocol, false);
        appendDlRow(sb, "Port", result.domain.port, false);
        appendDlRow(sb, "Path", result.domain.path, false);
        if (result.domain.queryParamCount > 0) {
            appendDlRow(sb, "Query Parameters", result.domain.queryParamCount + " (Values Redacted)", false);
        }
        if (result.reputation != null && result.reputation.checked) {
            sb.append("          <div class=\"dl-block\">\n");
            sb.append("            <dt>External Reputation Status</dt>\n");
            sb.append("            <dd class=\"meta-mono\">").append(htmlEscape(result.reputation.summaryLabel)).append("</dd>\n");
            sb.append("          </div>\n");
        }
        sb.append("          <div class=\"dl-block\">\n");
        sb.append("            <dt>Sanitized URL</dt>\n");
        sb.append("            <dd class=\"meta-mono break-all\">").append(htmlEscape(result.domain.redactedUrl)).append("</dd>\n");
        sb.append("          </div>\n");
        sb.append("        </dl>\n");
        sb.append("      </section>\n");

        sb.append("    </div>\n");
        sb.append("  </div>\n");
        sb.append("</main>\n");

        appendChatAdvisor(sb, chatOpen, chatRole, chatMessages, chatError, result);
        appendFooter(sb, result.disclaimer);
        appendDocumentEnd(sb);
        return sb.toString();
    }

    private static void appendDlRow(StringBuilder sb, String label, String value, boolean highlight) {
        sb.append("          <div class=\"dl-row\">\n");
        sb.append("            <dt>").append(htmlEscape(label)).append("</dt>\n");
        sb.append("            <dd class=\"meta-mono").append(highlight ? " tone-terracotta fw-700" : "").append("\">")
          .append(htmlEscape(value)).append("</dd>\n");
        sb.append("          </div>\n");
    }

    private static void appendNavbar(StringBuilder sb, boolean hasResult, String activeUrl, boolean chatOpen) {
        String toggleChatHref;
        if (hasResult && activeUrl != null && !activeUrl.isBlank()) {
            toggleChatHref = "/scan?url=" + urlEncode(activeUrl) + (chatOpen ? "" : "&chat=open");
        } else {
            toggleChatHref = chatOpen ? "/" : "/?chat=open";
        }

        sb.append("<header class=\"top-navbar\">\n");
        sb.append("  <div class=\"navbar-inner\">\n");
        sb.append("    <a href=\"/\" class=\"brand-wordmark\">\n");
        sb.append("      <span class=\"brand-shield-icon\"><svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.13 8.78-7 9.88-3.87-1.1-7-5.34-7-9.88V6.3l7-3.12z\"/></svg></span>\n");
        sb.append("      <span>CyberShield AI</span>\n");
        sb.append("    </a>\n");
        sb.append("    <nav class=\"nav-links\" aria-label=\"Primary Navigation\">\n");
        sb.append("      <a href=\"/\" class=\"nav-link\">URL Scanner</a>\n");
        sb.append("      <a href=\"/#diagnostic-presets\" class=\"nav-link\">Diagnostic Presets</a>\n");
        sb.append("      <a href=\"/#recent-history\" class=\"nav-link\">Recent History</a>\n");
        sb.append("      <a href=\"/#safety-rules\" class=\"nav-link\">Safety Rules</a>\n");
        sb.append("    </nav>\n");
        sb.append("    <div class=\"nav-cta\">\n");
        sb.append("      <a href=\"").append(htmlEscape(toggleChatHref)).append("\" id=\"btn-nav-advisor\" class=\"btn-nav-action\">\n");
        sb.append("        <svg width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z\"/></svg>\n");
        sb.append("        <span>").append(chatOpen ? "Hide AI Advisor" : "AI Security Advisor").append("</span>\n");
        sb.append("      </a>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");
        sb.append("</header>\n");
    }

    private static void appendChatAdvisor(
        StringBuilder sb,
        boolean chatOpen,
        String chatRole,
        List<ChatMessageView> messages,
        String chatError,
        ScanResultModel.ScanResult activeResult
    ) {
        String activeUrl = activeResult != null ? activeResult.domain.redactedUrl : "";
        String openHref = activeUrl.isEmpty()
            ? "/?chat=open"
            : "/scan?url=" + urlEncode(activeUrl) + "&chat=open";
        String closeHref = activeUrl.isEmpty()
            ? "/"
            : "/scan?url=" + urlEncode(activeUrl);

        sb.append("<div id=\"chat-launcher-container\" class=\"chat-launcher-wrap ").append(chatOpen ? "hidden" : "").append("\">\n");
        sb.append("  <a href=\"").append(htmlEscape(openHref)).append("\" id=\"btn-open-chat\" data-testid=\"chatbot-toggle-button\" aria-label=\"Open CyberShield Security Advisor\" class=\"chat-launcher-btn\">\n");
        sb.append("    <span class=\"chat-launcher-icon\" aria-hidden=\"true\"><svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z\"/></svg></span>\n");
        sb.append("    <span>\n");
        sb.append("      <strong class=\"chat-launcher-title\">AI Security Advisor</strong>\n");
        sb.append("      <span class=\"chat-launcher-sub\">Ask questions about link safety</span>\n");
        sb.append("    </span>\n");
        sb.append("  </a>\n");
        sb.append("</div>\n");

        String roleLabel = "URL Threat Analyst";
        if ("scam-educator".equalsIgnoreCase(chatRole)) {
            roleLabel = "Scam & Phishing Educator";
        } else if ("incident-advisor".equalsIgnoreCase(chatRole)) {
            roleLabel = "Incident Safety Advisor";
        }

        sb.append("<aside id=\"chat-drawer-panel\" data-testid=\"chatbot-drawer\" aria-label=\"CyberShield Security Advisor\" class=\"chat-drawer ").append(chatOpen ? "" : "hidden").append("\">\n");
        sb.append("  <div class=\"chat-header\">\n");
        sb.append("    <div class=\"chat-header-text\">\n");
        sb.append("      <h2 class=\"chat-header-title\">CyberShield Security Advisor</h2>\n");
        sb.append("      <p id=\"chat-role-label\" class=\"chat-header-sub\">").append(htmlEscape(roleLabel)).append("</p>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"chat-header-actions\">\n");
        sb.append("      <button type=\"button\" id=\"btn-reset-chat\" class=\"chat-mini-btn\">Reset</button>\n");
        sb.append("      <a href=\"").append(htmlEscape(closeHref)).append("\" id=\"btn-close-chat\" aria-label=\"Close Security Advisor\" class=\"chat-mini-btn\">✕</a>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        // Role Form
        sb.append("  <div class=\"chat-config-bar\">\n");
        sb.append("    <input type=\"hidden\" id=\"active-chat-url\" value=\"").append(htmlEscape(activeUrl)).append("\" />\n");
        sb.append("    <div class=\"chat-select-row\">\n");
        sb.append("      <label for=\"chatbot-role-select\">Advisor Mode:</label>\n");
        sb.append("      <select id=\"chatbot-role-select\" name=\"rolePreset\" data-testid=\"chatbot-role-select\" class=\"chat-select\">\n");
        appendOption(sb, "threat-analyst", "URL Threat Analyst", chatRole);
        appendOption(sb, "scam-educator", "Scam & Phishing Educator", chatRole);
        appendOption(sb, "incident-advisor", "Incident Safety Advisor", chatRole);
        sb.append("      </select>\n");
        sb.append("    </div>\n");
        if (activeResult != null) {
            sb.append("    <div class=\"chat-context-line meta-mono\">Target: ")
              .append(htmlEscape(activeResult.domain.hostname)).append(" (")
              .append(activeResult.riskScore).append("/100)</div>\n");
        }
        sb.append("  </div>\n");

        // Conversation Thread
        sb.append("  <div id=\"chat-messages-container\" data-testid=\"gemini-chat-thread\" class=\"chat-thread\">\n");
        if (messages != null) {
            for (ChatMessageView msg : messages) {
                boolean isUser = "user".equalsIgnoreCase(msg.role);
                sb.append("    <div class=\"chat-msg-row ").append(isUser ? "chat-user" : "chat-model").append("\">\n");
                sb.append("      <div class=\"chat-bubble\">\n");
                sb.append("        <div class=\"chat-text\">").append(htmlEscape(msg.text)).append("</div>\n");
                if (msg.timestamp != null && !msg.timestamp.isBlank()) {
                    sb.append("        <div class=\"chat-meta\">").append(htmlEscape(msg.timestamp)).append("</div>\n");
                }
                sb.append("      </div>\n");
                sb.append("    </div>\n");
            }
        }
        if (chatError != null && !chatError.isBlank()) {
            sb.append("    <div role=\"alert\" class=\"alert-error\">").append(htmlEscape(chatError)).append("</div>\n");
        }
        sb.append("  </div>\n");

        // Quick Starter Prompts
        String[] prompts = activeResult != null
            ? new String[]{
                "Explain why " + activeResult.domain.hostname + " scored " + activeResult.riskScore + "/100",
                "Is the registrable domain trustworthy?",
                "What safety steps should I follow for this link?"
            }
            : new String[]{
                "How do attackers use subdomains to spoof brands?",
                "What is a digital arrest scam link?",
                "I clicked a suspicious link—what should I do first?"
            };
        sb.append("  <div class=\"chat-prompts-bar\">\n");
        for (String p : prompts) {
            sb.append("    <button type=\"button\" class=\"chat-prompt-chip\" data-prompt=\"").append(htmlEscape(p)).append("\">")
              .append(htmlEscape(p)).append("</button>\n");
        }
        sb.append("  </div>\n");

        // Input Row
        sb.append("  <form id=\"chat-input-form\" action=\"/chat\" method=\"POST\" class=\"chat-input-bar\">\n");
        sb.append("    <input type=\"hidden\" name=\"activeUrl\" value=\"").append(htmlEscape(activeUrl)).append("\" />\n");
        sb.append("    <input type=\"hidden\" name=\"rolePreset\" value=\"").append(htmlEscape(chatRole)).append("\" />\n");
        sb.append("    <input data-testid=\"chatbot-input\" id=\"chat-user-input\" type=\"text\" name=\"message\" maxlength=\"500\" placeholder=\"Ask a security question about this link...\" aria-label=\"Chat message input\" class=\"chat-input\" />\n");
        sb.append("    <button type=\"button\" id=\"btn-chat-mic\" class=\"btn-chat-voice\" title=\"Dictate with microphone\" aria-label=\"Dictate with microphone\">\n");
        sb.append("      <svg width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z\"/><path d=\"M19 10v2a7 7 0 0 1-14 0v-2\"/><line x1=\"12\" y1=\"19\" x2=\"12\" y2=\"23\"/><line x1=\"8\" y1=\"23\" x2=\"16\" y2=\"23\"/></svg>\n");
        sb.append("    </button>\n");
        sb.append("    <button type=\"submit\" id=\"btn-chat-send\" data-testid=\"chatbot-send-button\" aria-label=\"Send chat message\" class=\"btn-primary chat-send-btn\">Send</button>\n");
        sb.append("  </form>\n");
        sb.append("</aside>\n");

        // Toast Notification Container
        sb.append("<div id=\"toast-container\" class=\"toast-container\" aria-live=\"polite\"></div>\n");
    }

    private static void appendOption(StringBuilder sb, String value, String label, String selectedValue) {
        sb.append("        <option value=\"").append(htmlEscape(value)).append("\"")
          .append(value.equalsIgnoreCase(selectedValue) ? " selected" : "")
          .append(">").append(htmlEscape(label)).append("</option>\n");
    }

    private static void appendFooter(StringBuilder sb, String disclaimer) {
        sb.append("<footer class=\"site-footer\">\n");
        sb.append("  <div class=\"footer-inner\">\n");
        sb.append("    <div class=\"footer-brand\">\n");
        sb.append("      <strong>CyberShield AI</strong>\n");
        sb.append("      <span class=\"footer-tagline\">· Deterministic Threat Engine</span>\n");
        sb.append("    </div>\n");
        sb.append("    <p class=\"footer-disclaimer\">").append(htmlEscape(disclaimer)).append("</p>\n");
        sb.append("  </div>\n");
        sb.append("</footer>\n");
    }

    private static void appendDocumentStart(StringBuilder sb, String title) {
        sb.append("<!DOCTYPE html>\n");
        sb.append("<html lang=\"en\" data-preferred-theme=\"light\">\n");
        sb.append("<head>\n");
        sb.append("  <meta charset=\"UTF-8\" />\n");
        sb.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n");
        sb.append("  <title>").append(htmlEscape(title)).append("</title>\n");
        sb.append("  <meta name=\"description\" content=\"CyberShield AI — URL Threat Detection &amp; Cybersecurity Awareness Platform for analyzing suspicious links, phishing patterns, deceptive domains, and brand impersonation.\" />\n");
        sb.append("  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />\n");
        sb.append("  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />\n");
        sb.append("  <link href=\"https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap\" rel=\"stylesheet\" />\n");
        sb.append("  <style>\n");
        sb.append("    :root {\n");
        sb.append("      --bg-canvas: #F7F4EE;\n");
        sb.append("      --bg-card: #FFFFFF;\n");
        sb.append("      --bg-subtle: #F3EFE9;\n");
        sb.append("      --bg-warm-tint: #FBEFE1;\n");
        sb.append("      --border-main: #E3DAD0;\n");
        sb.append("      --border-soft: #EDE6DC;\n");
        sb.append("      --text-main: #1C1917;\n");
        sb.append("      --text-body: #44403C;\n");
        sb.append("      --text-muted: #78716C;\n");
        sb.append("      --accent: #C2410C;\n");
        sb.append("      --accent-hover: #9A3412;\n");
        sb.append("      --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;\n");
        sb.append("      --font-mono: 'JetBrains Mono', monospace;\n");
        sb.append("      --shadow-sm: 0 1px 2px rgba(28,25,23,0.05);\n");
        sb.append("      --shadow-md: 0 4px 12px rgba(28,25,23,0.06), 0 1px 2px rgba(28,25,23,0.04);\n");
        sb.append("      --shadow-lg: 0 12px 32px rgba(28,25,23,0.12), 0 2px 6px rgba(28,25,23,0.06);\n");
        sb.append("    }\n");
        sb.append("    * { box-sizing: border-box; margin: 0; padding: 0; }\n");
        sb.append("    body {\n");
        sb.append("      background-color: var(--bg-canvas);\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      font-family: var(--font-sans);\n");
        sb.append("      line-height: 1.6;\n");
        sb.append("      min-height: 100vh;\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-direction: column;\n");
        sb.append("      -webkit-font-smoothing: antialiased;\n");
        sb.append("    }\n");
        sb.append("    .top-navbar {\n");
        sb.append("      background: var(--bg-card);\n");
        sb.append("      border-bottom: 1px solid var(--border-main);\n");
        sb.append("      position: sticky;\n");
        sb.append("      top: 0;\n");
        sb.append("      z-index: 30;\n");
        sb.append("      box-shadow: var(--shadow-sm);\n");
        sb.append("    }\n");
        sb.append("    .navbar-inner {\n");
        sb.append("      max-width: 1240px;\n");
        sb.append("      margin: 0 auto;\n");
        sb.append("      padding: 0.85rem 1.5rem;\n");
        sb.append("      display: flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: space-between;\n");
        sb.append("      gap: 1.5rem;\n");
        sb.append("    }\n");
        sb.append("    .brand-wordmark {\n");
        sb.append("      display: inline-flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      gap: 0.6rem;\n");
        sb.append("      font-size: 1.15rem;\n");
        sb.append("      font-weight: 800;\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      text-decoration: none;\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      flex-shrink: 0;\n");
        sb.append("      letter-spacing: -0.02em;\n");
        sb.append("    }\n");
        sb.append("    .brand-shield-icon {\n");
        sb.append("      color: var(--accent);\n");
        sb.append("      display: flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("    }\n");
        sb.append("    .nav-links {\n");
        sb.append("      display: flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      gap: 1.75rem;\n");
        sb.append("    }\n");
        sb.append("    .nav-link {\n");
        sb.append("      font-size: 0.875rem;\n");
        sb.append("      font-weight: 600;\n");
        sb.append("      color: var(--text-body);\n");
        sb.append("      text-decoration: none;\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      transition: color 0.15s ease;\n");
        sb.append("    }\n");
        sb.append("    .nav-link:hover { color: var(--accent); }\n");
        sb.append("    .btn-nav-action {\n");
        sb.append("      display: inline-flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      gap: 0.45rem;\n");
        sb.append("      padding: 0.5rem 1rem;\n");
        sb.append("      border-radius: 0.5rem;\n");
        sb.append("      background: var(--accent);\n");
        sb.append("      color: #FFFFFF;\n");
        sb.append("      font-size: 0.8125rem;\n");
        sb.append("      font-weight: 700;\n");
        sb.append("      text-decoration: none;\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      box-shadow: 0 1px 2px rgba(194,65,12,0.2);\n");
        sb.append("      transition: background 0.15s ease, transform 0.1s ease;\n");
        sb.append("    }\n");
        sb.append("    .btn-nav-action:hover { background: var(--accent-hover); transform: translateY(-1px); }\n");
        sb.append("    .main-content { flex: 1; padding: 2rem 1rem 3.5rem; }\n");
        sb.append("    .container-narrow { max-width: 980px; margin: 0 auto; }\n");
        sb.append("    .container-wide { max-width: 1240px; margin: 0 auto; }\n");
        sb.append("    .stack-lg > * + * { margin-top: 2rem; }\n");
        sb.append("    .stack-md > * + * { margin-top: 1.5rem; }\n");
        sb.append("    .card-editorial {\n");
        sb.append("      background: var(--bg-card);\n");
        sb.append("      border: 1px solid var(--border-main);\n");
        sb.append("      border-radius: 0.85rem;\n");
        sb.append("      box-shadow: var(--shadow-sm);\n");
        sb.append("    }\n");
        sb.append("    .overflow-hidden { overflow: hidden; }\n");
        sb.append("    .section-pad { padding: 1.75rem 2rem; }\n");
        sb.append("    .hero-masthead {\n");
        sb.append("      background: linear-gradient(180deg, #FDF4E8 0%, #FAF0E4 100%);\n");
        sb.append("      border-bottom: 1px solid var(--border-main);\n");
        sb.append("      padding: 2.75rem 2rem 2.25rem;\n");
        sb.append("      text-align: center;\n");
        sb.append("    }\n");
        sb.append("    .hero-badge {\n");
        sb.append("      display: inline-block;\n");
        sb.append("      font-size: 0.75rem;\n");
        sb.append("      font-weight: 700;\n");
        sb.append("      text-transform: uppercase;\n");
        sb.append("      letter-spacing: 0.05em;\n");
        sb.append("      color: var(--accent);\n");
        sb.append("      background: #FFFFFF;\n");
        sb.append("      border: 1px solid var(--border-soft);\n");
        sb.append("      padding: 0.3rem 0.85rem;\n");
        sb.append("      border-radius: 99px;\n");
        sb.append("      margin-bottom: 1rem;\n");
        sb.append("      box-shadow: 0 1px 2px rgba(0,0,0,0.03);\n");
        sb.append("    }\n");
        sb.append("    .hero-title {\n");
        sb.append("      font-size: clamp(1.85rem, 3.4vw, 2.75rem);\n");
        sb.append("      font-weight: 800;\n");
        sb.append("      line-height: 1.2;\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      max-width: 42rem;\n");
        sb.append("      margin: 0 auto;\n");
        sb.append("      letter-spacing: -0.025em;\n");
        sb.append("    }\n");
        sb.append("    .hero-subtitle {\n");
        sb.append("      margin: 1rem auto 0;\n");
        sb.append("      max-width: 44rem;\n");
        sb.append("      font-size: 0.95rem;\n");
        sb.append("      color: var(--text-body);\n");
        sb.append("      line-height: 1.6;\n");
        sb.append("    }\n");
        sb.append("    .console-body { padding: 2rem; }\n");
        sb.append("    .label-row {\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-wrap: wrap;\n");
        sb.append("      align-items: baseline;\n");
        sb.append("      justify-content: space-between;\n");
        sb.append("      gap: 0.5rem;\n");
        sb.append("      margin-bottom: 0.65rem;\n");
        sb.append("    }\n");
        sb.append("    .input-label { font-size: 0.875rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .meta-mono {\n");
        sb.append("      font-family: var(--font-mono);\n");
        sb.append("      font-size: 0.75rem;\n");
        sb.append("      color: var(--text-muted);\n");
        sb.append("      font-variant-numeric: tabular-nums;\n");
        sb.append("    }\n");
        sb.append("    .meta-quiet { font-size: 0.78rem; color: var(--text-muted); }\n");
        sb.append("    .scanner-bar {\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-wrap: wrap;\n");
        sb.append("      gap: 0.75rem;\n");
        sb.append("      align-items: stretch;\n");
        sb.append("    }\n");
        sb.append("    .input-wrapper { position: relative; flex: 1 1 320px; }\n");
        sb.append("    .input-icon {\n");
        sb.append("      position: absolute;\n");
        sb.append("      left: 1rem;\n");
        sb.append("      top: 50%;\n");
        sb.append("      transform: translateY(-50%);\n");
        sb.append("      color: var(--text-muted);\n");
        sb.append("      display: flex;\n");
        sb.append("      pointer-events: none;\n");
        sb.append("    }\n");
        sb.append("    .btn-voice-icon {\n");
        sb.append("      position: absolute;\n");
        sb.append("      right: 0.75rem;\n");
        sb.append("      top: 50%;\n");
        sb.append("      transform: translateY(-50%);\n");
        sb.append("      background: transparent;\n");
        sb.append("      border: none;\n");
        sb.append("      color: var(--text-muted);\n");
        sb.append("      padding: 0.35rem;\n");
        sb.append("      border-radius: 0.35rem;\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      display: flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: center;\n");
        sb.append("    }\n");
        sb.append("    .btn-voice-icon:hover { color: var(--accent); background: var(--bg-subtle); }\n");
        sb.append("    .btn-voice-icon.listening { color: #DC2626; animation: pulse 1.5s infinite; }\n");
        sb.append("    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }\n");
        sb.append("    .url-input {\n");
        sb.append("      width: 100%;\n");
        sb.append("      border: 1.5px solid var(--border-main);\n");
        sb.append("      background: var(--bg-card);\n");
        sb.append("      border-radius: 0.6rem;\n");
        sb.append("      padding: 0.85rem 2.5rem 0.85rem 2.75rem;\n");
        sb.append("      font-family: var(--font-mono);\n");
        sb.append("      font-size: 0.925rem;\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      transition: border-color 0.15s ease, box-shadow 0.15s ease;\n");
        sb.append("    }\n");
        sb.append("    .url-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(194,65,12,0.15); }\n");
        sb.append("    .button-group { display: flex; gap: 0.65rem; align-items: center; flex-wrap: wrap; }\n");
        sb.append("    .btn-primary {\n");
        sb.append("      display: inline-flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: center;\n");
        sb.append("      gap: 0.5rem;\n");
        sb.append("      background: var(--accent);\n");
        sb.append("      color: #FFFFFF;\n");
        sb.append("      border: none;\n");
        sb.append("      border-radius: 0.6rem;\n");
        sb.append("      padding: 0.85rem 1.4rem;\n");
        sb.append("      font-family: var(--font-sans);\n");
        sb.append("      font-size: 0.875rem;\n");
        sb.append("      font-weight: 700;\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      text-decoration: none;\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      box-shadow: 0 1px 2px rgba(194,65,12,0.25);\n");
        sb.append("      transition: background 0.15s ease, transform 0.1s ease;\n");
        sb.append("    }\n");
        sb.append("    .btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); }\n");
        sb.append("    .btn-secondary {\n");
        sb.append("      display: inline-flex;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: center;\n");
        sb.append("      gap: 0.4rem;\n");
        sb.append("      background: #FFFFFF;\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      border: 1px solid var(--border-main);\n");
        sb.append("      border-radius: 0.6rem;\n");
        sb.append("      padding: 0.85rem 1.15rem;\n");
        sb.append("      font-size: 0.8125rem;\n");
        sb.append("      font-weight: 600;\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      text-decoration: none;\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      box-shadow: var(--shadow-sm);\n");
        sb.append("      transition: background 0.15s ease, border-color 0.15s ease;\n");
        sb.append("    }\n");
        sb.append("    .btn-secondary:hover { border-color: var(--text-muted); background: var(--bg-subtle); }\n");
        sb.append("    .alert-error {\n");
        sb.append("      margin-top: 1rem;\n");
        sb.append("      padding: 1rem 1.25rem;\n");
        sb.append("      border-radius: 0.6rem;\n");
        sb.append("      border: 1px solid #FECACA;\n");
        sb.append("      background: #FEF2F2;\n");
        sb.append("      color: #991B1B;\n");
        sb.append("    }\n");
        sb.append("    .alert-title { font-weight: 700; font-size: 0.9rem; }\n");
        sb.append("    .alert-desc { font-size: 0.85rem; margin-top: 0.25rem; }\n");
        sb.append("    .privacy-strip {\n");
        sb.append("      margin-top: 1.25rem;\n");
        sb.append("      padding-top: 1rem;\n");
        sb.append("      border-top: 1px solid var(--border-soft);\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-wrap: wrap;\n");
        sb.append("      justify-content: space-between;\n");
        sb.append("      gap: 0.5rem;\n");
        sb.append("      font-size: 0.75rem;\n");
        sb.append("      color: var(--text-muted);\n");
        sb.append("    }\n");
        sb.append("    .presets-block {\n");
        sb.append("      margin-top: 1.5rem;\n");
        sb.append("      padding-top: 1.5rem;\n");
        sb.append("      border-top: 1px solid var(--border-soft);\n");
        sb.append("    }\n");
        sb.append("    .section-subhead { font-size: 0.875rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .presets-grid {\n");
        sb.append("      display: grid;\n");
        sb.append("      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));\n");
        sb.append("      gap: 0.75rem;\n");
        sb.append("      margin-top: 0.75rem;\n");
        sb.append("    }\n");
        sb.append("    .preset-form { margin: 0; }\n");
        sb.append("    .preset-card {\n");
        sb.append("      width: 100%;\n");
        sb.append("      text-align: left;\n");
        sb.append("      background: #FFFFFF;\n");
        sb.append("      border: 1px solid var(--border-soft);\n");
        sb.append("      border-radius: 0.6rem;\n");
        sb.append("      padding: 0.85rem 1rem;\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      font-family: var(--font-sans);\n");
        sb.append("      transition: all 0.15s ease;\n");
        sb.append("      box-shadow: 0 1px 2px rgba(0,0,0,0.02);\n");
        sb.append("    }\n");
        sb.append("    .preset-card:hover { border-color: var(--accent); background: var(--bg-warm-tint); transform: translateY(-1px); box-shadow: var(--shadow-sm); }\n");
        sb.append("    .preset-card-top { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }\n");
        sb.append("    .preset-title { font-size: 0.82rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .preset-arrow { font-size: 0.85rem; color: var(--accent); font-weight: 700; }\n");
        sb.append("    .preset-url {\n");
        sb.append("      margin-top: 0.3rem;\n");
        sb.append("      font-family: var(--font-mono);\n");
        sb.append("      font-size: 0.72rem;\n");
        sb.append("      color: var(--text-muted);\n");
        sb.append("      white-space: nowrap;\n");
        sb.append("      overflow: hidden;\n");
        sb.append("      text-overflow: ellipsis;\n");
        sb.append("    }\n");
        sb.append("    .section-header {\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-wrap: wrap;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: space-between;\n");
        sb.append("      gap: 1rem;\n");
        sb.append("      padding-bottom: 1rem;\n");
        sb.append("      border-bottom: 1px solid var(--border-soft);\n");
        sb.append("    }\n");
        sb.append("    .section-title {\n");
        sb.append("      font-size: 1.25rem;\n");
        sb.append("      font-weight: 800;\n");
        sb.append("      color: var(--text-main);\n");
        sb.append("      letter-spacing: -0.015em;\n");
        sb.append("    }\n");
        sb.append("    .badge-finding {\n");
        sb.append("      font-size: 0.72rem;\n");
        sb.append("      font-weight: 700;\n");
        sb.append("      background: var(--bg-subtle);\n");
        sb.append("      color: var(--text-body);\n");
        sb.append("      padding: 0.25rem 0.65rem;\n");
        sb.append("      border-radius: 99px;\n");
        sb.append("      border: 1px solid var(--border-soft);\n");
        sb.append("    }\n");
        sb.append("    .header-actions { display: flex; align-items: center; gap: 0.75rem; }\n");
        sb.append("    .inline-form { display: inline; }\n");
        sb.append("    .btn-clear-history {\n");
        sb.append("      background: #FFFFFF;\n");
        sb.append("      border: 1px solid var(--border-main);\n");
        sb.append("      border-radius: 0.45rem;\n");
        sb.append("      padding: 0.35rem 0.75rem;\n");
        sb.append("      font-size: 0.75rem;\n");
        sb.append("      font-weight: 600;\n");
        sb.append("      color: var(--text-body);\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      transition: all 0.15s ease;\n");
        sb.append("    }\n");
        sb.append("    .btn-clear-history:hover { background: #FEF2F2; border-color: #FECACA; color: #991B1B; }\n");
        sb.append("    .empty-state { padding: 2.5rem 1rem; text-align: center; }\n");
        sb.append("    .empty-title { font-size: 0.95rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .empty-desc { font-size: 0.825rem; color: var(--text-muted); max-width: 30rem; margin: 0.35rem auto 0; }\n");
        sb.append("    .history-list { list-style: none; }\n");
        sb.append("    .history-row + .history-row { border-top: 1px solid var(--border-soft); }\n");
        sb.append("    .history-item-form { margin: 0; }\n");
        sb.append("    .history-item-btn {\n");
        sb.append("      width: 100%;\n");
        sb.append("      background: transparent;\n");
        sb.append("      border: none;\n");
        sb.append("      padding: 1rem 0.5rem;\n");
        sb.append("      display: flex;\n");
        sb.append("      flex-wrap: wrap;\n");
        sb.append("      align-items: center;\n");
        sb.append("      justify-content: space-between;\n");
        sb.append("      gap: 1rem;\n");
        sb.append("      text-align: left;\n");
        sb.append("      cursor: pointer;\n");
        sb.append("      font-family: var(--font-sans);\n");
        sb.append("      border-radius: 0.5rem;\n");
        sb.append("      transition: background 0.15s ease;\n");
        sb.append("    }\n");
        sb.append("    .history-item-btn:hover { background: var(--bg-subtle); }\n");
        sb.append("    .history-left { display: flex; align-items: center; gap: 0.85rem; min-width: 0; flex: 1; }\n");
        sb.append("    .history-idx { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); width: 1.5rem; }\n");
        sb.append("    .mini-gauge { position: relative; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }\n");
        sb.append("    .gauge-svg { transform: rotate(-90deg); }\n");
        sb.append("    .mini-gauge-score { position: absolute; font-family: var(--font-mono); font-size: 0.68rem; font-weight: 700; }\n");
        sb.append("    .history-domain-meta { min-width: 0; flex: 1; }\n");
        sb.append("    .history-host-line { display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; }\n");
        sb.append("    .history-hostname { font-family: var(--font-mono); font-size: 0.875rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .history-url { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 460px; }\n");
        sb.append("    .history-right { display: flex; align-items: center; gap: 1.25rem; flex-shrink: 0; }\n");
        sb.append("    .history-score-text { font-family: var(--font-mono); font-size: 0.78rem; display: flex; align-items: center; gap: 0.35rem; }\n");
        sb.append("    .mini-bar-track { margin-top: 0.35rem; width: 7.5rem; height: 6px; background: #E5DFD5; border-radius: 99px; overflow: hidden; }\n");
        sb.append("    .mini-bar-fill { height: 100%; }\n");
        sb.append("    .view-report-cta { font-size: 0.78rem; font-weight: 700; color: var(--accent); white-space: nowrap; }\n");
        sb.append("    .rules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.25rem; margin-top: 1.25rem; }\n");
        sb.append("    .rule-item { display: flex; gap: 0.75rem; font-size: 0.85rem; color: var(--text-body); }\n");
        sb.append("    .rule-item strong { display: block; color: var(--text-main); margin-bottom: 0.2rem; font-weight: 700; }\n");
        sb.append("    .rule-num { font-family: var(--font-mono); font-weight: 800; color: var(--accent); flex-shrink: 0; }\n");
        sb.append("    .back-row { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; }\n");
        sb.append("    .back-link { font-size: 0.875rem; font-weight: 700; color: var(--accent); text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem; }\n");
        sb.append("    .back-link:hover { text-decoration: underline; }\n");
        sb.append("    .back-actions { display: flex; align-items: center; gap: 1rem; }\n");
        sb.append("    .btn-copy { display: inline-flex; align-items: center; gap: 0.35rem; background: #FFFFFF; border: 1px solid var(--border-main); border-radius: 0.45rem; padding: 0.35rem 0.75rem; font-size: 0.75rem; font-weight: 600; color: var(--text-body); cursor: pointer; }\n");
        sb.append("    .btn-copy:hover { border-color: var(--accent); color: var(--accent); }\n");
        sb.append("    .anatomy-header { background: var(--bg-warm-tint); border-bottom: 1px solid var(--border-main); padding: 0.85rem 1.5rem; display: flex; justify-content: space-between; align-items: center; gap: 1rem; font-size: 0.8rem; }\n");
        sb.append("    .anatomy-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }\n");
        sb.append("    .anatomy-cell { padding: 1rem 1.25rem; border-right: 1px solid var(--border-soft); }\n");
        sb.append("    .anatomy-cell:last-child { border-right: none; }\n");
        sb.append("    .anatomy-highlight { background: #FEF9F3; }\n");
        sb.append("    .anatomy-label { font-size: 0.7rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }\n");
        sb.append("    .anatomy-val { font-family: var(--font-mono); font-size: 0.85rem; margin-top: 0.25rem; overflow-wrap: anywhere; word-break: break-all; }\n");
        sb.append("    .dashboard-grid-12 { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.5rem; align-items: stretch; }\n");
        sb.append("    .col-span-7 { grid-column: span 7; }\n");
        sb.append("    .col-span-5 { grid-column: span 5; }\n");
        sb.append("    @media (max-width: 960px) { .col-span-7, .col-span-5 { grid-column: span 12; } .nav-links { display: none; } }\n");
        sb.append("    .flex-col-between { display: flex; flex-direction: column; justify-content: space-between; }\n");
        sb.append("    .score-hero-row { display: flex; flex-wrap: wrap; align-items: center; gap: 2rem; margin-top: 1.5rem; }\n");
        sb.append("    .gauge-container { position: relative; width: 160px; height: 160px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin: 0 auto; }\n");
        sb.append("    .gauge-center { position: absolute; text-align: center; display: flex; flex-direction: column; align-items: center; }\n");
        sb.append("    .gauge-big-num { font-family: var(--font-mono); font-size: 2.4rem; font-weight: 800; line-height: 1; }\n");
        sb.append("    .score-summary-col { flex: 1 1 260px; }\n");
        sb.append("    .classification-pill { display: inline-block; padding: 0.35rem 0.85rem; border-radius: 99px; font-size: 0.82rem; font-weight: 800; letter-spacing: 0.02em; text-transform: uppercase; }\n");
        sb.append("    .summary-prose { margin-top: 0.65rem; font-size: 0.925rem; color: var(--text-body); line-height: 1.55; }\n");
        sb.append("    .linear-meter-block { margin-top: 1.25rem; }\n");
        sb.append("    .meter-track { height: 10px; background: #E5DFD5; border-radius: 99px; overflow: hidden; }\n");
        sb.append("    .meter-fill { height: 100%; border-radius: 99px; }\n");
        sb.append("    .meter-ticks { display: flex; justify-content: space-between; font-size: 0.68rem; margin-top: 0.35rem; color: var(--text-muted); }\n");
        sb.append("    .disclaimer-box { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-soft); font-size: 0.75rem; color: var(--text-muted); }\n");
        sb.append("    .primary-advice { margin-top: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-soft); font-size: 0.925rem; font-weight: 700; }\n");
        sb.append("    .guidance-list { list-style: none; margin-top: 1rem; }\n");
        sb.append("    .guidance-list li { display: flex; gap: 0.65rem; font-size: 0.85rem; color: var(--text-body); margin-bottom: 0.65rem; }\n");
        sb.append("    .action-bar-footer { margin-top: 1.5rem; padding-top: 1.25rem; border-top: 1px solid var(--border-soft); display: flex; flex-wrap: wrap; gap: 0.65rem; }\n");
        sb.append("    .indicator-list { margin-top: 0.5rem; }\n");
        sb.append("    .indicator-article { padding: 1.25rem 0; border-bottom: 1px solid var(--border-soft); }\n");
        sb.append("    .indicator-article:last-child { border-bottom: none; padding-bottom: 0; }\n");
        sb.append("    .indicator-top { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 0.5rem; }\n");
        sb.append("    .indicator-title { font-size: 0.95rem; font-weight: 700; color: var(--text-main); }\n");
        sb.append("    .indicator-exp { margin-top: 0.45rem; font-size: 0.875rem; color: var(--text-body); }\n");
        sb.append("    .indicator-comp { margin-top: 0.45rem; font-size: 0.78rem; color: var(--text-muted); }\n");
        sb.append("    .indicator-comp code { font-family: var(--font-mono); font-weight: 600; color: var(--accent); background: var(--bg-subtle); padding: 0.15rem 0.35rem; border-radius: 0.3rem; word-break: break-all; }\n");
        sb.append("    .indicator-why { margin-top: 0.45rem; font-size: 0.78rem; color: var(--text-muted); }\n");
        sb.append("    .domain-dl { margin-top: 0.5rem; font-size: 0.825rem; }\n");
        sb.append("    .dl-row { display: flex; justify-content: space-between; gap: 1rem; padding: 0.65rem 0; border-bottom: 1px solid var(--border-soft); }\n");
        sb.append("    .dl-row dt, .dl-block dt { color: var(--text-muted); font-weight: 500; }\n");
        sb.append("    .dl-row dd { text-align: right; word-break: break-all; color: var(--text-main); font-weight: 600; }\n");
        sb.append("    .dl-block { padding: 0.65rem 0; border-bottom: 1px solid var(--border-soft); }\n");
        sb.append("    .dl-block:last-child { border-bottom: none; }\n");
        sb.append("    .dl-block dd { margin-top: 0.25rem; color: var(--text-body); }\n");
        sb.append("    .break-all { word-break: break-all; }\n");
        sb.append("    .truncate-text { max-width: 480px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n");
        sb.append("    .sep { color: #C5BCB2; margin: 0 0.2rem; }\n");
        sb.append("    .fw-500 { font-weight: 500; } .fw-600 { font-weight: 600; } .fw-700 { font-weight: 700; }\n");
        sb.append("    .tone-emerald { color: #047857; } .tone-amber { color: #B45309; } .tone-orange { color: #C2410C; } .tone-rose { color: #BE123C; } .tone-red { color: #B91C1C; } .tone-terracotta { color: #C2410C; } .tone-muted { color: #78716C; }\n");
        sb.append("    .bar-emerald { background: #059669; } .bar-amber { background: #D97706; } .bar-orange { background: #EA580C; } .bar-rose { background: #E11D48; } .bar-red { background: #DC2626; }\n");
        sb.append("    .chat-launcher-wrap { position: fixed; bottom: 1.25rem; right: 1.25rem; z-index: 40; }\n");
        sb.append("    .chat-launcher-wrap.hidden { display: none !important; }\n");
        sb.append("    .chat-launcher-btn { display: inline-flex; align-items: center; gap: 0.75rem; background: #FFFFFF; border: 1.5px solid var(--border-main); border-radius: 99px; padding: 0.65rem 1.15rem 0.65rem 0.65rem; text-decoration: none; color: var(--text-main); box-shadow: var(--shadow-lg); transition: all 0.2s ease; }\n");
        sb.append("    .chat-launcher-btn:hover { border-color: var(--accent); transform: translateY(-2px); }\n");
        sb.append("    .chat-launcher-icon { width: 2.2rem; height: 2.2rem; border-radius: 99px; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }\n");
        sb.append("    .chat-launcher-title { display: block; font-size: 0.85rem; font-weight: 700; }\n");
        sb.append("    .chat-launcher-sub { display: block; font-size: 0.7rem; color: var(--text-muted); }\n");
        sb.append("    .chat-drawer { position: fixed; bottom: 1rem; right: 1rem; z-index: 50; width: min(440px, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); background: #FFFFFF; border: 1.5px solid var(--border-main); border-radius: 1rem; box-shadow: var(--shadow-lg); overflow: hidden; display: flex; flex-direction: column; transition: transform 0.25s ease, opacity 0.2s ease; }\n");
        sb.append("    .chat-drawer.hidden { display: none !important; }\n");
        sb.append("    .chat-header { background: var(--bg-warm-tint); border-bottom: 1px solid var(--border-main); padding: 0.85rem 1rem; display: flex; justify-content: space-between; align-items: center; }\n");
        sb.append("    .chat-header-title { font-size: 0.95rem; font-weight: 800; color: var(--text-main); letter-spacing: -0.01em; }\n");
        sb.append("    .chat-header-sub { font-size: 0.7rem; color: var(--text-muted); font-weight: 600; }\n");
        sb.append("    .chat-header-actions { display: flex; gap: 0.4rem; align-items: center; }\n");
        sb.append("    .chat-mini-btn { background: #FFFFFF; border: 1px solid var(--border-main); border-radius: 0.4rem; padding: 0.25rem 0.55rem; font-size: 0.72rem; font-weight: 600; color: var(--text-body); text-decoration: none; cursor: pointer; }\n");
        sb.append("    .chat-mini-btn:hover { background: var(--bg-subtle); color: var(--text-main); }\n");
        sb.append("    .chat-config-bar { background: var(--bg-subtle); border-bottom: 1px solid var(--border-soft); padding: 0.6rem 1rem; font-size: 0.72rem; }\n");
        sb.append("    .chat-select-row { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }\n");
        sb.append("    .chat-select { flex: 1; padding: 0.3rem 0.5rem; border: 1px solid var(--border-main); border-radius: 0.35rem; background: #FFFFFF; font-size: 0.75rem; font-family: var(--font-sans); font-weight: 600; }\n");
        sb.append("    .chat-context-line { margin-top: 0.35rem; padding-top: 0.35rem; border-top: 1px solid var(--border-soft); color: var(--accent); font-weight: 600; }\n");
        sb.append("    .chat-thread { height: 280px; max-height: 40vh; overflow-y: auto; padding: 0.85rem 1rem; background: #FFFFFF; display: flex; flex-direction: column; gap: 0.65rem; scroll-behavior: smooth; }\n");
        sb.append("    .chat-msg-row { display: flex; }\n");
        sb.append("    .chat-user { justify-content: flex-end; }\n");
        sb.append("    .chat-model { justify-content: flex-start; }\n");
        sb.append("    .chat-bubble { max-width: 85%; padding: 0.65rem 0.9rem; border-radius: 0.85rem; font-size: 0.8rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }\n");
        sb.append("    .chat-user .chat-bubble { background: var(--accent); color: #fff; border-bottom-right-radius: 0.2rem; }\n");
        sb.append("    .chat-model .chat-bubble { background: var(--bg-subtle); border: 1px solid var(--border-soft); color: var(--text-main); border-bottom-left-radius: 0.2rem; }\n");
        sb.append("    .chat-meta { font-size: 0.65rem; opacity: 0.75; margin-top: 0.25rem; font-family: var(--font-mono); }\n");
        sb.append("    .chat-prompts-bar { display: flex; gap: 0.4rem; overflow-x: auto; padding: 0.5rem 0.75rem; background: var(--bg-subtle); border-top: 1px solid var(--border-soft); }\n");
        sb.append("    .chat-prompt-chip { flex-shrink: 0; background: #FFFFFF; border: 1px solid var(--border-soft); border-radius: 0.35rem; padding: 0.25rem 0.55rem; font-size: 0.68rem; color: var(--text-body); cursor: pointer; white-space: nowrap; }\n");
        sb.append("    .chat-prompt-chip:hover { border-color: var(--accent); color: var(--accent); background: var(--bg-warm-tint); }\n");
        sb.append("    .chat-input-bar { display: flex; gap: 0.5rem; padding: 0.65rem 0.75rem; border-top: 1px solid var(--border-soft); background: #FFFFFF; align-items: center; }\n");
        sb.append("    .chat-input { flex: 1; border: 1.5px solid var(--border-main); border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.8rem; background: #FFFFFF; color: var(--text-main); }\n");
        sb.append("    .chat-input:focus { outline: none; border-color: var(--accent); }\n");
        sb.append("    .btn-chat-voice { background: transparent; border: none; color: var(--text-muted); padding: 0.4rem; border-radius: 0.4rem; cursor: pointer; display: flex; align-items: center; justify-content: center; }\n");
        sb.append("    .btn-chat-voice:hover { color: var(--accent); background: var(--bg-subtle); }\n");
        sb.append("    .btn-chat-voice.listening { color: #DC2626; animation: pulse 1.5s infinite; }\n");
        sb.append("    .chat-send-btn { padding: 0.5rem 1rem; font-size: 0.8rem; border-radius: 0.5rem; }\n");
        sb.append("    .site-footer { background: #FFFFFF; border-top: 1px solid var(--border-soft); padding: 1.75rem 1.5rem; margin-top: 2rem; }\n");
        sb.append("    .footer-inner { max-width: 1240px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem; font-size: 0.78rem; color: var(--text-muted); }\n");
        sb.append("    .footer-brand strong { font-weight: 800; color: var(--text-main); font-size: 0.9rem; }\n");
        sb.append("    .footer-disclaimer { max-width: 38rem; text-align: right; line-height: 1.5; }\n");
        sb.append("    .toast-container { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 100; display: flex; flex-direction: column; gap: 0.5rem; pointer-events: none; }\n");
        sb.append("    .toast-item { background: #1C1917; color: #FFFFFF; padding: 0.65rem 1rem; border-radius: 0.5rem; font-size: 0.8rem; font-weight: 600; box-shadow: var(--shadow-lg); transition: all 0.25s ease; animation: toastIn 0.2s ease; }\n");
        sb.append("    @keyframes toastIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }\n");
        sb.append("    @media (max-width: 640px) {\n");
        sb.append("      .footer-disclaimer { text-align: left; }\n");
        sb.append("      .console-body, .section-pad { padding: 1.25rem; }\n");
        sb.append("      .hero-masthead { padding: 2rem 1.25rem 1.75rem; }\n");
        sb.append("      .chat-drawer { width: 100vw; right: 0; bottom: 0; border-radius: 1rem 1rem 0 0; max-height: 80vh; }\n");
        sb.append("      .chat-thread { height: 220px; }\n");
        sb.append("      .chat-launcher-wrap { bottom: 1rem; right: 1rem; }\n");
        sb.append("    }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n");
        sb.append("<body>\n");
    }

    private static void appendDocumentEnd(StringBuilder sb) {
        sb.append("<script>\n");
        sb.append("(function() {\n");
        sb.append("  // Client-Side Utilities for Instant Interactivity\n");
        sb.append("  function showToast(msg) {\n");
        sb.append("    var c = document.getElementById('toast-container');\n");
        sb.append("    if (!c) return;\n");
        sb.append("    var t = document.createElement('div');\n");
        sb.append("    t.className = 'toast-item';\n");
        sb.append("    t.textContent = msg;\n");
        sb.append("    c.appendChild(t);\n");
        sb.append("    setTimeout(function() {\n");
        sb.append("      t.style.opacity = '0';\n");
        sb.append("      setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 300);\n");
        sb.append("    }, 2500);\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  // Safe Clipboard Copy Helper (with fallback for headless & restricted environments)\n");
        sb.append("  function copyTextSafely(text) {\n");
        sb.append("    if (!text) return;\n");
        sb.append("    function fallback() {\n");
        sb.append("      try {\n");
        sb.append("        var ta = document.createElement('textarea');\n");
        sb.append("        ta.value = text;\n");
        sb.append("        ta.style.position = 'fixed';\n");
        sb.append("        ta.style.left = '-9999px';\n");
        sb.append("        ta.style.top = '0';\n");
        sb.append("        ta.setAttribute('readonly', '');\n");
        sb.append("        document.body.appendChild(ta);\n");
        sb.append("        ta.select();\n");
        sb.append("        try { document.execCommand('copy'); } catch(e) {}\n");
        sb.append("        document.body.removeChild(ta);\n");
        sb.append("        showToast('Sanitized URL copied');\n");
        sb.append("      } catch(err) {\n");
        sb.append("        showToast('URL: ' + (text.length > 30 ? text.substring(0, 30) + '...' : text));\n");
        sb.append("      }\n");
        sb.append("    }\n");
        sb.append("    try {\n");
        sb.append("      if (navigator.clipboard && window.isSecureContext) {\n");
        sb.append("        navigator.clipboard.writeText(text).then(function() {\n");
        sb.append("          showToast('Sanitized URL copied');\n");
        sb.append("        }).catch(function() {\n");
        sb.append("          fallback();\n");
        sb.append("        });\n");
        sb.append("      } else {\n");
        sb.append("        fallback();\n");
        sb.append("      }\n");
        sb.append("    } catch(e) {\n");
        sb.append("      fallback();\n");
        sb.append("    }\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  var copyBtn = document.getElementById('btn-copy-url');\n");
        sb.append("  if (copyBtn) {\n");
        sb.append("    copyBtn.addEventListener('click', function() {\n");
        sb.append("      var text = copyBtn.getAttribute('data-copy');\n");
        sb.append("      copyTextSafely(text);\n");
        sb.append("    });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  // Chat Drawer Smooth Toggle\n");
        sb.append("  var drawer = document.getElementById('chat-drawer-panel');\n");
        sb.append("  var launcher = document.getElementById('chat-launcher-container');\n");
        sb.append("  var navAdvisorBtn = document.getElementById('btn-nav-advisor');\n");
        sb.append("  var openBtn = document.getElementById('btn-open-chat');\n");
        sb.append("  var closeBtn = document.getElementById('btn-close-chat');\n");
        sb.append("  var chatThread = document.getElementById('chat-messages-container');\n");
        sb.append("\n");
        sb.append("  function openDrawer(e) {\n");
        sb.append("    if (e) e.preventDefault();\n");
        sb.append("    if (drawer) drawer.classList.remove('hidden');\n");
        sb.append("    if (launcher) launcher.classList.add('hidden');\n");
        sb.append("    if (navAdvisorBtn) navAdvisorBtn.querySelector('span').textContent = 'Hide AI Advisor';\n");
        sb.append("    scrollChat();\n");
        sb.append("    var inp = document.getElementById('chat-user-input');\n");
        sb.append("    if (inp) inp.focus();\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function closeDrawer(e) {\n");
        sb.append("    if (e) e.preventDefault();\n");
        sb.append("    if (drawer) drawer.classList.add('hidden');\n");
        sb.append("    if (launcher) launcher.classList.remove('hidden');\n");
        sb.append("    if (navAdvisorBtn) navAdvisorBtn.querySelector('span').textContent = 'AI Security Advisor';\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function scrollChat() {\n");
        sb.append("    if (chatThread) chatThread.scrollTop = chatThread.scrollHeight;\n");
        sb.append("  }\n");
        sb.append("  scrollChat();\n");
        sb.append("\n");
        sb.append("  if (openBtn) openBtn.addEventListener('click', openDrawer);\n");
        sb.append("  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);\n");
        sb.append("  if (navAdvisorBtn) {\n");
        sb.append("    navAdvisorBtn.addEventListener('click', function(e) {\n");
        sb.append("      if (drawer && !drawer.classList.contains('hidden')) {\n");
        sb.append("        closeDrawer(e);\n");
        sb.append("      } else {\n");
        sb.append("        openDrawer(e);\n");
        sb.append("      }\n");
        sb.append("    });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  // Asynchronous Chat Messaging (No Page Reload)\n");
        sb.append("  var chatForm = document.getElementById('chat-input-form');\n");
        sb.append("  var chatInput = document.getElementById('chat-user-input');\n");
        sb.append("  var roleSelect = document.getElementById('chatbot-role-select');\n");
        sb.append("  var activeUrlInput = document.getElementById('active-chat-url');\n");
        sb.append("  var resetBtn = document.getElementById('btn-reset-chat');\n");
        sb.append("\n");
        sb.append("  if (resetBtn) {\n");
        sb.append("    resetBtn.addEventListener('click', function() {\n");
        sb.append("      if (chatThread) {\n");
        sb.append("        chatThread.innerHTML = '<div class=\"chat-msg-row chat-model\"><div class=\"chat-bubble\"><div class=\"chat-text\">Conversation reset. Ask me any question about link safety or URL indicators.</div></div></div>';\n");
        sb.append("        showToast('Advisor reset');\n");
        sb.append("      }\n");
        sb.append("    });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function appendChatMsg(role, text) {\n");
        sb.append("    if (!chatThread) return;\n");
        sb.append("    var row = document.createElement('div');\n");
        sb.append("    row.className = 'chat-msg-row ' + (role === 'user' ? 'chat-user' : 'chat-model');\n");
        sb.append("    var bubble = document.createElement('div');\n");
        sb.append("    bubble.className = 'chat-bubble';\n");
        sb.append("    var txt = document.createElement('div');\n");
        sb.append("    txt.className = 'chat-text';\n");
        sb.append("    txt.textContent = text;\n");
        sb.append("    bubble.appendChild(txt);\n");
        sb.append("    row.appendChild(bubble);\n");
        sb.append("    chatThread.appendChild(row);\n");
        sb.append("    scrollChat();\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  function sendChatMessage(msgText) {\n");
        sb.append("    if (!msgText || !msgText.trim()) return;\n");
        sb.append("    var text = msgText.trim();\n");
        sb.append("    appendChatMsg('user', text);\n");
        sb.append("    if (chatInput) chatInput.value = '';\n");
        sb.append("\n");
        sb.append("    var role = roleSelect ? roleSelect.value : 'threat-analyst';\n");
        sb.append("    var activeUrl = activeUrlInput ? activeUrlInput.value : '';\n");
        sb.append("    var payload = {\n");
        sb.append("      message: text,\n");
        sb.append("      rolePreset: role,\n");
        sb.append("      scanContext: activeUrl ? 'Target: ' + activeUrl : ''\n");
        sb.append("    };\n");
        sb.append("\n");
        sb.append("    fetch('/api/chat', {\n");
        sb.append("      method: 'POST',\n");
        sb.append("      headers: { 'Content-Type': 'application/json' },\n");
        sb.append("      body: JSON.stringify(payload)\n");
        sb.append("    })\n");
        sb.append("    .then(function(res) { return res.json(); })\n");
        sb.append("    .then(function(data) {\n");
        sb.append("      appendChatMsg('model', data.reply || 'Analysis completed.');\n");
        sb.append("    })\n");
        sb.append("    .catch(function() {\n");
        sb.append("      appendChatMsg('model', 'Advisor guidance: Always verify domains directly on official portals before entering credentials.');\n");
        sb.append("    });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  if (chatForm) {\n");
        sb.append("    chatForm.addEventListener('submit', function(e) {\n");
        sb.append("      e.preventDefault();\n");
        sb.append("      if (chatInput) sendChatMessage(chatInput.value);\n");
        sb.append("    });\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  // Quick Starter Prompts Click Handler\n");
        sb.append("  var promptChips = document.querySelectorAll('.chat-prompt-chip');\n");
        sb.append("  promptChips.forEach(function(chip) {\n");
        sb.append("    chip.addEventListener('click', function(e) {\n");
        sb.append("      e.preventDefault();\n");
        sb.append("      var p = chip.getAttribute('data-prompt');\n");
        sb.append("      if (p) sendChatMessage(p);\n");
        sb.append("    });\n");
        sb.append("  });\n");
        sb.append("\n");
        sb.append("  // Voice / Microphone Speech-to-Text Support\n");
        sb.append("  function setupVoice(btn, targetInput, isSubmitOnResult) {\n");
        sb.append("    if (!btn || !targetInput) return;\n");
        sb.append("    var SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;\n");
        sb.append("    if (!SpeechRec) {\n");
        sb.append("      btn.title = 'Speech recognition not supported in this browser';\n");
        sb.append("      return;\n");
        sb.append("    }\n");
        sb.append("    var rec = new SpeechRec();\n");
        sb.append("    rec.continuous = false;\n");
        sb.append("    rec.interimResults = false;\n");
        sb.append("    rec.lang = 'en-US';\n");
        sb.append("    var listening = false;\n");
        sb.append("\n");
        sb.append("    btn.addEventListener('click', function(e) {\n");
        sb.append("      e.preventDefault();\n");
        sb.append("      if (listening) {\n");
        sb.append("        rec.stop();\n");
        sb.append("        return;\n");
        sb.append("      }\n");
        sb.append("      try {\n");
        sb.append("        rec.start();\n");
        sb.append("        listening = true;\n");
        sb.append("        btn.classList.add('listening');\n");
        sb.append("        showToast('Listening... Speak URL or question');\n");
        sb.append("      } catch(err) {}\n");
        sb.append("    });\n");
        sb.append("\n");
        sb.append("    rec.onresult = function(ev) {\n");
        sb.append("      listening = false;\n");
        sb.append("      btn.classList.remove('listening');\n");
        sb.append("      if (ev.results && ev.results[0] && ev.results[0][0]) {\n");
        sb.append("        var spoken = ev.results[0][0].transcript.trim();\n");
        sb.append("        targetInput.value = spoken;\n");
        sb.append("        showToast('Dictated: ' + spoken);\n");
        sb.append("        if (isSubmitOnResult && spoken) {\n");
        sb.append("          sendChatMessage(spoken);\n");
        sb.append("        }\n");
        sb.append("      }\n");
        sb.append("    };\n");
        sb.append("    rec.onerror = function() {\n");
        sb.append("      listening = false;\n");
        sb.append("      btn.classList.remove('listening');\n");
        sb.append("    };\n");
        sb.append("    rec.onend = function() {\n");
        sb.append("      listening = false;\n");
        sb.append("      btn.classList.remove('listening');\n");
        sb.append("    };\n");
        sb.append("  }\n");
        sb.append("\n");
        sb.append("  setupVoice(document.getElementById('btn-voice-input'), document.getElementById('url-scanner-input'), false);\n");
        sb.append("  setupVoice(document.getElementById('btn-chat-mic'), document.getElementById('chat-user-input'), false);\n");
        sb.append("})();\n");
        sb.append("</script>\n");
        sb.append("</body>\n</html>\n");
    }
}
