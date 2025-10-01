package dev.AliAhmedBG.phish;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;

import java.io.ByteArrayInputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;


/**
 * Core analyzer: takes raw .eml bytes and reads key headers.
 * applies a couple of simple phishing heuristics, and returns a ScoringResult.
 */
public class EmailHeaderAnalyser {

    // Analyses a raw .eml file and returns a scoring result
    public ScoringResult analyze(byte[] emlBytes) {
        try {
            // Jakarta Mail needs a Session to parse messages so an empty properties object is passed
            Session session = Session.getInstance(new Properties());

            // Builds a MimeMessage from the raw bytes so headers can be read like "From", "Return-Path", etc
            MimeMessage msg = new MimeMessage(session, new ByteArrayInputStream(emlBytes));

            // Pulls out headers that are required
            // If a header is missing the helpers return null
            String from = firstHeader(msg, "From");
            String returnPath = firstHeader(msg, "Return-Path");
            String authResults = firstHeader(msg, "Authentication-Results");
            // for the MVP only one header can be read
            // An extension would be to be able to analyse more than one
            String received = firstHeader(msg, "Received");

            // human readable findings are collected to be printed to the CLI
            Map<String, String> findings = new LinkedHashMap<>();
            findings.put("From", shown(from));
            findings.put("Return-Path", shown(returnPath));
            findings.put("Received", (received == null ? "-" : "present"));
            findings.put("Authentication-Results", (authResults == null ? "-" : authResults));

            // starts as neutral
            int score = 0;

            // Rule 1: From vs Return-Path domain mismatch
            // Checks if the sending domain in 'From' is different from the envelope sender in 'Return-Path',
            String dFrom = extractDomain(from);
            String dReturn = extractDomain(returnPath);

            if (!dFrom.isEmpty() && !dReturn.isEmpty() && !dFrom.equalsIgnoreCase(dReturn)) {
                findings.put("From/Return-Path", "MISMATCH");
                score += 70;
            } else {
                findings.put("From/Return-Path", "match/unknown");
            }

            // Rule 2: SPF/DKIM hints from Authentication-Results

            // Many servers add a summary header like:
            // Simple "pass"/"fail" keywords are searched for for SPF or DKIM.
            if (authResults != null) {
                String lower = authResults.toLowerCase();
                if (lower.contains("spf=fail") || lower.contains("dkim=fail")) {
                    findings.put("Auth-Result-Status", "fail");
                    score += 30;
                } else if (lower.contains("spf=pass") || lower.contains("dkim=pass")) {
                    findings.put("Auth-Result-Status", "pass");
                    score -= 10;
                } else {
                    findings.put("Auth-Result-Status", "present");
                }
            } else {
                findings.put("Auth-Result-Status", "missing");
            }

            // Rule 3: received chain presence
            // its unusual for real mail if there's no Received header at all
            if (received == null || received.isBlank()) {
                score += 10;
            }

            // Clamp score into [0, 100] and map to a label
            int finalScore = Math.max(0, Math.min(100, score));
            String label = finalScore >= 60 ? "Suspicious" : "Safe";

            // Package the result for Main to output
            return new ScoringResult(finalScore, label, findings);

        } catch (Exception e) {
            // For this MVP any checked exceptions are wrapped into a RuntimeException with context.
            throw new RuntimeException("Failed to parse EML: " + e.getMessage(), e);
        }
    }

    // Safely read the first value of a header from the message
    // Returns null if the header doesn't exist or can't be read
    private static String firstHeader(MimeMessage m, String name) {
        try {
            String[] vals = m.getHeader(name);
            if (vals == null || vals.length == 0) return null;
            return vals[0];
        } catch (Exception e) {
            return null;
        }
    }

    // Show "-" instead of null/blank, so output looks clean.
    private static String shown(String s) {
        return (s == null || s.isBlank()) ? "-" : s;
    }

     // Extract the domain part from a header like:
     // "Support <help@example.com>"  -> "example.com"
     // "help@example.com"            -> "example.com"
     // If we can't find an email address, return "".
    private static String extractDomain(String headerValue) {
        if (headerValue == null) return "";
        String s = headerValue;

        // If the email is in angle brackets, grab what's inside <...>
        int lt = s.indexOf('<'), gt = s.indexOf('>');
        if (lt >= 0 && gt > lt) s = s.substring(lt + 1, gt);

        // Take the substring after '@'
        int at = s.indexOf('@');
        if (at >= 0 && at + 1 < s.length()) {
            return s.substring(at + 1).trim().toLowerCase();
        }
        return "";
    }
}
