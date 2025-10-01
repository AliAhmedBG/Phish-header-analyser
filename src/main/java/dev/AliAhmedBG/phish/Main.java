package dev.AliAhmedBG.phish;

// for reading all bytes from a file
import java.nio.file.Files;
// To represent the file path
import java.nio.file.Path;
// To loop through the results map
import java.util.Map;

/**
 * Main entrypoint for the Phish Header Analyzer CLI.
 * Usage: java -jar phish-header-analyzer.jar <path-to.eml>
 */
public class Main {
    public static void main(String[] args) throws Exception {
        // Step 1: Check arguments
        // If no argument is provided, tell the user how to run it and exit.
        if (args.length < 1) {
            System.out.println("Usage: java -jar phish-header-analyzer.jar <path-to.eml>");
            System.exit(1);
        }

        // Step 2: Read the .eml file
        // Turns the first argument into a Path object
        Path p = Path.of(args[0]);
        byte[] raw = Files.readAllBytes(p);

        // Step 3: Analyze
        // Create an analyser object
        EmailHeaderAnalyser analyser = new EmailHeaderAnalyser();
        // Pass the file bytes into it, get back a ScoringResult
        ScoringResult result = analyser.analyze(raw);

        // Step 4: Print results
        System.out.println("---- Phishing Header Analysis ----");

        // Loop through each key/value finding and print them
        for (Map.Entry<String, String> e : result.getFindings().entrySet()) {
            System.out.printf("%-25s : %s%n", e.getKey(), e.getValue());
        }

        System.out.println("--------------------------------");

        // Print the overall score and label
        System.out.printf("SCORE: %d   →   %s%n", result.getScore(), result.getLabel());
    }
}
