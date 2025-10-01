package dev.AliAhmedBG.phish;

import java.util.Map;

// Class that holds the results from analysing the email
public class ScoringResult {
    // these are all the fields that this class holds
    private final int score;
    private final String label;
    private final Map<String, String> findings;

    // Constructor method
    public ScoringResult(int score, String label, Map<String, String> findings) {
        this.score = score;
        this.label = label;
        this.findings = findings;
    }

    // Getter methods
    // returns the score of the email
    public int getScore() {
        return score;
    }

    // returns labels (safe / suspicious)
    public String getLabel() {
        return label;
    }

    // returns the map of the findings
    public Map<String, String> getFindings() {
        return findings;
    }
}
