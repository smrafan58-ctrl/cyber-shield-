import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * ScanResultModel — Pure Java 17 domain models and report formatters for CyberShield AI.
 */
public class ScanResultModel {

    public static class ExamplePreset {
        public final String label;
        public final String url;
        public final String description;

        public ExamplePreset(String label, String url, String description) {
            this.label = label;
            this.url = url;
            this.description = description;
        }
    }

    public static final List<ExamplePreset> DIAGNOSTIC_PRESETS = List.of(
        new ExamplePreset(
            "Benign Reference Domain",
            "https://www.wikipedia.org",
            "Standard HTTPS official domain with zero risk indicators"
        ),
        new ExamplePreset(
            "Unencrypted HTTP Link",
            "http://example.com",
            "Plaintext HTTP protocol warning (+8 pts)"
        ),
        new ExamplePreset(
            "Subdomain Brand Spoofing",
            "https://google.com.security-check.example.org",
            "Trusted brand placed in subdomain of unrelated registrable domain"
        ),
        new ExamplePreset(
            "Typosquatting + Login Path",
            "https://paypa1-example.com/login",
            "Homoglyph substitution (paypa1) combined with /login route"
        ),
        new ExamplePreset(
            "Account Verification Route",
            "https://example.com/account/verify",
            "Sensitive account verification path on generic domain"
        ),
        new ExamplePreset(
            "Raw IP + Non-Standard Port",
            "http://192.168.1.250:8080/banking/login?session=active",
            "Numeric IP host, custom port 8080, HTTP, and redacted query value"
        )
    );

    public static class IndicatorItem {
        public final String id;
        public final String name;
        public final String severity;
        public final int weight;
        public final String explanation;
        public final String component;
        public final String reasonItMatters;

        public IndicatorItem(
            String id,
            String name,
            String severity,
            int weight,
            String explanation,
            String component,
            String reasonItMatters
        ) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.weight = weight;
            this.explanation = explanation;
            this.component = component;
            this.reasonItMatters = reasonItMatters;
        }
    }

    public static class DomainDetails {
        public final String originalInput;
        public final String normalizedUrl;
        public final String redactedUrl;
        public final String protocol;
        public final String hostname;
        public final String registrableDomain;
        public final String subdomain;
        public final String tld;
        public final String port;
        public final String path;
        public final int urlLength;
        public final int hostnameLength;
        public final int queryParamCount;
        public final List<String> queryParamKeys;
        public final boolean hasCredentialsInAuthority;
        public final boolean isIpAddress;
        public final boolean isPunycode;

        public DomainDetails(
            String originalInput,
            String normalizedUrl,
            String redactedUrl,
            String protocol,
            String hostname,
            String registrableDomain,
            String subdomain,
            String tld,
            String port,
            String path,
            int urlLength,
            int hostnameLength,
            int queryParamCount,
            List<String> queryParamKeys,
            boolean hasCredentialsInAuthority,
            boolean isIpAddress,
            boolean isPunycode
        ) {
            this.originalInput = redactedUrl;
            this.normalizedUrl = redactedUrl;
            this.redactedUrl = redactedUrl;
            this.protocol = protocol;
            this.hostname = hostname;
            this.registrableDomain = registrableDomain;
            this.subdomain = subdomain;
            this.tld = tld;
            this.port = port;
            this.path = path;
            this.urlLength = urlLength;
            this.hostnameLength = hostnameLength;
            this.queryParamCount = queryParamCount;
            this.queryParamKeys = queryParamKeys != null
                ? new ArrayList<>(queryParamKeys)
                : Collections.emptyList();
            this.hasCredentialsInAuthority = hasCredentialsInAuthority;
            this.isIpAddress = isIpAddress;
            this.isPunycode = isPunycode;
        }
    }

    public static class ReputationStatus {
        public final boolean checked;
        public final String status;
        public final String summaryLabel;
        public final String providerName;
        public final String lastCheckedAt;

        public ReputationStatus(
            boolean checked,
            String status,
            String summaryLabel,
            String providerName,
            String lastCheckedAt
        ) {
            this.checked = checked;
            this.status = status;
            this.summaryLabel = summaryLabel;
            this.providerName = providerName;
            this.lastCheckedAt = lastCheckedAt;
        }
    }

    public static class GuidanceDetails {
        public final String headline;
        public final String primaryAdvice;
        public final List<String> universalRules;

        public GuidanceDetails(String headline, String primaryAdvice, List<String> universalRules) {
            this.headline = headline;
            this.primaryAdvice = primaryAdvice;
            this.universalRules = universalRules != null
                ? new ArrayList<>(universalRules)
                : Collections.emptyList();
        }
    }

    public static class ScanResult {
        public final String id;
        public final String timestamp;
        public final int riskScore;
        public final String classification;
        public final String summaryExplanation;
        public final String disclaimer;
        public final DomainDetails domain;
        public final List<IndicatorItem> indicators;
        public final ReputationStatus reputation;
        public final GuidanceDetails guidance;
        public final String rawResultJson;

        public ScanResult(
            String id,
            String timestamp,
            int riskScore,
            String classification,
            String summaryExplanation,
            String disclaimer,
            DomainDetails domain,
            List<IndicatorItem> indicators,
            ReputationStatus reputation,
            GuidanceDetails guidance,
            String rawResultJson
        ) {
            this.id = id;
            this.timestamp = timestamp;
            this.riskScore = riskScore;
            this.classification = classification;
            this.summaryExplanation = summaryExplanation;
            this.disclaimer = disclaimer;
            this.domain = domain;
            this.indicators = indicators != null
                ? new ArrayList<>(indicators)
                : Collections.emptyList();
            this.reputation = reputation;
            this.guidance = guidance;
            this.rawResultJson = rawResultJson;
        }
    }

    public static class AnalysisOutcome {
        public final boolean valid;
        public final String errorTitle;
        public final String errorMessage;
        public final ScanResult result;
        public final String responseJson;

        private AnalysisOutcome(
            boolean valid,
            String errorTitle,
            String errorMessage,
            ScanResult result,
            String responseJson
        ) {
            this.valid = valid;
            this.errorTitle = errorTitle;
            this.errorMessage = errorMessage;
            this.result = result;
            this.responseJson = responseJson;
        }

        public static AnalysisOutcome invalid(String errorTitle, String errorMessage, String responseJson) {
            return new AnalysisOutcome(false, errorTitle, errorMessage, null, responseJson);
        }

        public static AnalysisOutcome success(ScanResult result, String responseJson) {
            return new AnalysisOutcome(true, null, null, result, responseJson);
        }
    }

    public static String formatTxtReport(ScanResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("====================================================================\n");
        sb.append("CYBERSHIELD AI - URL THREAT ASSESSMENT REPORT\n");
        sb.append("====================================================================\n\n");
        sb.append("Timestamp (UTC)    : ").append(r.timestamp).append("\n");
        sb.append("Sanitized URL      : ").append(r.domain.redactedUrl).append("\n");
        sb.append("Composite Score    : ").append(r.riskScore).append(" / 100\n");
        sb.append("Classification     : ").append(r.classification).append("\n");
        sb.append("Summary Assessment : ").append(r.summaryExplanation).append("\n\n");

        sb.append("--------------------------------------------------------------------\n");
        sb.append("1. EXTRACTED DOMAIN & URL ANATOMY\n");
        sb.append("--------------------------------------------------------------------\n");
        sb.append("Hostname           : ").append(r.domain.hostname).append("\n");
        sb.append("Registrable Domain : ").append(r.domain.registrableDomain).append("\n");
        sb.append("Subdomain          : ").append(r.domain.subdomain).append("\n");
        sb.append("Top-Level Domain   : ").append(r.domain.tld).append("\n");
        sb.append("Protocol           : ").append(r.domain.protocol).append("\n");
        sb.append("Port               : ").append(r.domain.port).append("\n");
        sb.append("Path               : ").append(r.domain.path).append("\n");
        if (r.domain.queryParamCount > 0) {
            sb.append("Query Parameters   : ").append(r.domain.queryParamCount).append(" (Values Redacted)\n");
        }
        if (r.reputation != null && r.reputation.checked) {
            sb.append("Reputation Status  : ").append(r.reputation.summaryLabel).append("\n");
        }
        sb.append("\n");

        sb.append("--------------------------------------------------------------------\n");
        sb.append("2. DETECTED RISK INDICATORS (").append(r.indicators.size()).append(" TRIGGERED)\n");
        sb.append("--------------------------------------------------------------------\n");
        if (r.indicators.isEmpty()) {
            sb.append("No suspicious structural or lexical URL heuristics were triggered.\n\n");
        } else {
            for (int i = 0; i < r.indicators.size(); i++) {
                IndicatorItem ind = r.indicators.get(i);
                sb.append(String.format("0%d. %s [Severity: %s | +%d pts]\n", i + 1, ind.name, ind.severity, ind.weight));
                sb.append("    Component      : ").append(ind.component).append("\n");
                sb.append("    Explanation    : ").append(ind.explanation).append("\n");
                sb.append("    Why It Matters : ").append(ind.reasonItMatters).append("\n\n");
            }
        }

        sb.append("--------------------------------------------------------------------\n");
        sb.append("3. RECOMMENDED SAFETY ACTIONS\n");
        sb.append("--------------------------------------------------------------------\n");
        sb.append("Headline           : ").append(r.guidance.headline).append("\n");
        sb.append("Primary Advice     : ").append(r.guidance.primaryAdvice).append("\n");
        for (int i = 0; i < r.guidance.universalRules.size(); i++) {
            sb.append("  0").append(i + 1).append(". ").append(r.guidance.universalRules.get(i)).append("\n");
        }
        sb.append("\n--------------------------------------------------------------------\n");
        sb.append("MANDATORY DISCLAIMER\n");
        sb.append("--------------------------------------------------------------------\n");
        sb.append(r.disclaimer).append("\n");
        return sb.toString();
    }

    public static String formatScanContextForAdvisor(ScanResult r) {
        if (r == null) return "";
        StringBuilder indSb = new StringBuilder();
        if (r.indicators.isEmpty()) {
            indSb.append("None triggered");
        } else {
            for (int i = 0; i < r.indicators.size(); i++) {
                if (i > 0) indSb.append("; ");
                IndicatorItem ind = r.indicators.get(i);
                indSb.append(ind.name).append(" (").append(ind.severity).append(", +").append(ind.weight).append(" pts)");
            }
        }
        return "Sanitized URL: " + r.domain.redactedUrl + "\n"
            + "Hostname: " + r.domain.hostname + "\n"
            + "Registrable Domain: " + r.domain.registrableDomain + "\n"
            + "Subdomain: " + r.domain.subdomain + "\n"
            + "Protocol: " + r.domain.protocol + "\n"
            + "Risk Score: " + r.riskScore + "/100 (" + r.classification + ")\n"
            + "Triggered Indicators: " + indSb;
    }
}
