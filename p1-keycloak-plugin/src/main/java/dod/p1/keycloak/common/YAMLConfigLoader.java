package dod.p1.keycloak.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for loading YAML configuration with environment variable substitution.
 */
public final class YAMLConfigLoader {

    /** Pattern to match environment variable placeholders in the format ${VAR_NAME}. */
    private static final Pattern ENV_VAR_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");

    /**
     * Private constructor to prevent instantiation.
     */
    private YAMLConfigLoader() {
        // Utility class
    }

    /**
     * Substitutes environment variables in the configuration content.
     * Supports ${VAR_NAME} syntax.
     *
     * @param content The YAML content with potential environment variables
     * @return The content with environment variables substituted
     */
    public static String substituteEnvironmentVariables(final String content) {
        Matcher matcher = ENV_VAR_PATTERN.matcher(content);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            String varName = matcher.group(1);
            String value = System.getenv(varName);

            if (value != null) {
                // Escape special characters in replacement string
                matcher.appendReplacement(result, Matcher.quoteReplacement(value));
            } else {
                // Keep the original placeholder if env var not found
                matcher.appendReplacement(result, Matcher.quoteReplacement(matcher.group(0)));
            }
        }
        matcher.appendTail(result);

        return result.toString();
    }
}
