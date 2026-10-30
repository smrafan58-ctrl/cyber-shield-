import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ScanHistoryJavaStore — Pure Java 17 store for the last 5 analyzed URLs.
 * Deduplicates by normalizedUrl (case-insensitive) and maintains newest-first order
 * with a strict maximum of 5 items.
 */
public class ScanHistoryJavaStore {

    public static final int MAX_HISTORY_ITEMS = 5;

    private static class HistoryEntry {
        final String key;
        final String resultJson;
        final ScanResultModel.ScanResult structuredResult;

        HistoryEntry(String key, String resultJson, ScanResultModel.ScanResult structuredResult) {
            this.key = key;
            this.resultJson = resultJson;
            this.structuredResult = structuredResult;
        }
    }

    private final List<HistoryEntry> entries = new ArrayList<>();

    public synchronized void recordResult(String resultObjectJson) {
        recordStructuredResult(resultObjectJson, null);
    }

    public synchronized void recordStructuredResult(String resultObjectJson, ScanResultModel.ScanResult structuredResult) {
        if (resultObjectJson == null || resultObjectJson.isBlank()) {
            return;
        }
        String key = structuredResult != null && structuredResult.domain != null
            ? structuredResult.domain.normalizedUrl.trim().toLowerCase()
            : extractNormalizedKey(resultObjectJson);
        entries.removeIf(e -> e.key.equalsIgnoreCase(key));
        entries.add(0, new HistoryEntry(key, resultObjectJson, structuredResult));
        while (entries.size() > MAX_HISTORY_ITEMS) {
            entries.remove(entries.size() - 1);
        }
    }

    public synchronized List<ScanResultModel.ScanResult> getRecentScans() {
        List<ScanResultModel.ScanResult> list = new ArrayList<>();
        for (HistoryEntry entry : entries) {
            if (entry.structuredResult != null) {
                list.add(entry.structuredResult);
            }
        }
        return Collections.unmodifiableList(list);
    }

    public synchronized ScanResultModel.ScanResult findByUrl(String url) {
        if (url == null || url.isBlank()) return null;
        String clean = url.trim().toLowerCase();
        for (HistoryEntry entry : entries) {
            if (entry.structuredResult != null) {
                if (entry.key.equalsIgnoreCase(clean)
                    || entry.structuredResult.domain.originalInput.equalsIgnoreCase(clean)
                    || entry.structuredResult.domain.redactedUrl.equalsIgnoreCase(clean)) {
                    return entry.structuredResult;
                }
            }
        }
        return null;
    }

    public synchronized void clear() {
        entries.clear();
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized String toJsonArray() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(entries.get(i).resultJson);
        }
        sb.append("]");
        return sb.toString();
    }

    private static String extractNormalizedKey(String json) {
        Pattern p = Pattern.compile("\"normalizedUrl\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1).trim().toLowerCase();
        }
        Pattern hostP = Pattern.compile("\"hostname\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher hostM = hostP.matcher(json);
        if (hostM.find()) {
            return hostM.group(1).trim().toLowerCase();
        }
        return String.valueOf(json.hashCode());
    }
}
