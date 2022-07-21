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

    public SigmaRegularExpression(String regexp) throws SigmaRegularExpressionError {
        this.regexp = regexp.replace(" ", "_ws_");
        this.compile();
    }

    public void compile() throws SigmaRegularExpressionError {
        try {
            Pattern.compile(this.regexp);
        } catch (Exception ex) {
            throw new SigmaRegularExpressionError("Regular expression '" + this.regexp + "' is invalid: " + ex.getMessage());
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

    public void setRegexp(String regexp) {
        this.regexp = regexp;
    }

    @Override
    public String toString() {
        return this.regexp;
    }
}