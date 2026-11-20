/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaRegularExpression implements SigmaType {

    private String regexp;

    private String original;

    public SigmaRegularExpression(String regexp) throws SigmaRegularExpressionError {
        this.original = regexp;
        this.regexp = regexp.replace(" ", "_ws_");
        this.compile();
    }

    public void compile() throws SigmaRegularExpressionError {
        try {
            Pattern.compile(this.original);
        } catch (Exception ex) {
            throw new SigmaRegularExpressionError("Regular expression '" + this.original + "' is invalid: " + ex.getMessage());
        }
    }

    public String escape(List<String> escaped, String escapeChar) {
        if (escapeChar == null || escapeChar.isEmpty()) {
            escapeChar = "\\";
        }

        List<String> rList = new ArrayList<>();
        for (String escape: escaped) {
            rList.add(Pattern.quote(escape));
        }
        rList.add(Pattern.quote(escapeChar));
        String r = String.join("|", rList);

        List<Integer> pos = new ArrayList<>();
        pos.add(0);

        Pattern pattern = Pattern.compile(r);
        Matcher matcher = pattern.matcher(this.regexp);

        while (matcher.find()) {
            pos.add(matcher.start());
        }
        pos.add(this.regexp.length());

        List<String> ranges = new ArrayList<>();
        for (int i = 0; i < pos.size()-1; ++i) {
            ranges.add(this.regexp.substring(pos.get(i), pos.get(i+1)));
        }
        return String.join(escapeChar, ranges);
    }

    public String getRegexp() {
        return regexp;
    }

    /** The lossless pattern for native queries, including subsequent regex modifiers. */
    public String getOriginal() {
        return original;
    }

    public void setRegexp(String regexp) {
        this.original = regexp;
        this.regexp = regexp;
    }

    /** Apply contains/startswith/endswith to the raw pattern without decoding legacy whitespace markers. */
    public void wrapPattern(boolean leadingWildcard, boolean trailingWildcard) {
        // Preserve historical query_string rendering, including its anchor handling.
        if (leadingWildcard && !regexp.startsWith(".*") && !regexp.startsWith("^")) {
            regexp = ".*" + regexp;
        }
        if (trailingWildcard && !regexp.endsWith(".*") && !regexp.endsWith("$")) {
            regexp += ".*";
        }

        // Wrapping an alternation must apply to every branch, not just the first/last one.
        boolean alternation = hasTopLevelAlternation(original);
        String pattern = alternation ? "(" + original + ")" : original;
        boolean prefix = leadingWildcard && (alternation || !original.startsWith(".*")) && !original.startsWith("^");
        boolean suffix = trailingWildcard && (alternation || !original.endsWith(".*")) && !hasEndAnchor(original);
        original = (prefix ? ".*" : "") + pattern + (suffix ? ".*" : "");
    }

    private static boolean hasEndAnchor(String pattern) {
        if (!pattern.endsWith("$")) {
            return false;
        }
        int backslashes = 0;
        for (int i = pattern.length() - 2; i >= 0 && pattern.charAt(i) == '\\'; i--) {
            backslashes++;
        }
        return backslashes % 2 == 0;
    }

    private static boolean hasTopLevelAlternation(String pattern) {
        int depth = 0;
        boolean escaped = false;
        boolean characterClass = false;
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '[') {
                characterClass = true;
            } else if (c == ']') {
                characterClass = false;
            } else if (!characterClass) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == '|' && depth == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return this.regexp;
    }
}