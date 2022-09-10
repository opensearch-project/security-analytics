/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaString implements SigmaType {

    public class SpecialChars {
        public static final char WILDCARD_MULTI = '*';
        public static final char WILDCARD_SINGLE = '?';
        public static final char ESCAPE_CHAR = '\\';
    }

    private String original;

    private List<AnyOneOf<String, Character, Placeholder>> sOpt;

    public SigmaString(String s) {
        if (s == null) {
            s = "";
        }
//        s = s.replace(" ", "_ws_");

        this.original = s;
        int sLen = s.length();

        List<AnyOneOf<String, Character, Placeholder>> r = new ArrayList<>();
        StringBuilder acc = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < sLen; i++) {
            if (escaped) {
                if (s.charAt(i) == SpecialChars.WILDCARD_MULTI || s.charAt(i) == SpecialChars.WILDCARD_SINGLE
                    || s.charAt(i) == SpecialChars.ESCAPE_CHAR) {
                    acc.append(s.charAt(i));
                } else {
                    acc.append(SpecialChars.ESCAPE_CHAR).append(s.charAt(i));
                }
                escaped = false;
            } else if (s.charAt(i) == SpecialChars.ESCAPE_CHAR) {
                escaped = true;
            } else {
                if (s.charAt(i) == SpecialChars.WILDCARD_MULTI || s.charAt(i) == SpecialChars.WILDCARD_SINGLE) {
                    if (!acc.toString().equals("")) {
                        r.add(AnyOneOf.leftVal(acc.toString()));
                    }

                    switch (s.charAt(i)) {
                        case SpecialChars.WILDCARD_MULTI:
                            r.add(AnyOneOf.middleVal(SpecialChars.WILDCARD_MULTI));
                            break;
                        case SpecialChars.WILDCARD_SINGLE:
                            r.add(AnyOneOf.middleVal(SpecialChars.WILDCARD_SINGLE));
                    }
                    acc = new StringBuilder();
                } else {
                    acc.append(s.charAt(i));
                }
            }
        }

        if (escaped) {
            acc.append(SpecialChars.ESCAPE_CHAR);
        }
        if (!acc.toString().equals("")) {
            r.add(AnyOneOf.leftVal(acc.toString()));
        }

        this.sOpt = r;
    }

    public void mergeStrings() {
        List<AnyOneOf<String, Character, Placeholder>> mergedOpts = new ArrayList<>();

        int size = this.sOpt.size();
        for (int i = 0; i < size; ++i) {
            int mSize = mergedOpts.size();
            if (mSize > 0 && mergedOpts.get(mSize-1).isLeft() && this.sOpt.get(i).isLeft()) {
                mergedOpts.set(mSize-1, AnyOneOf.leftVal(mergedOpts.get(mSize-1).getLeft() + this.sOpt.get(i).getLeft()));
            } else {
                mergedOpts.add(this.sOpt.get(i));
            }
        }
        this.sOpt = mergedOpts;
    }

    public SigmaString append(AnyOneOf<String, Character, Placeholder> other) {
        this.sOpt.add(other);
        this.mergeStrings();
        return this;
    }

    public SigmaString prepend(AnyOneOf<String, Character, Placeholder> other) {
        this.sOpt.add(0, other);
        this.mergeStrings();
        return this;
    }

    public int length() {
        int sum = 0;
        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isLeft()) {
                sum += sOptElem.getLeft().length();
            } else {
                ++sum;
            }
        }
        return sum;
    }

    public boolean startsWith(Either<String, Character> val) {
        AnyOneOf<String, Character, Placeholder> c = this.sOpt.get(0);
        if (val.isLeft()) {
            return c.isLeft() && c.getLeft().startsWith(val.getLeft());
        } else if (val.isRight()) {
            return c.isMiddle() && c.getMiddle() == val.get();
        }
        return false;
    }

    public boolean endsWith(Either<String, Character> val) {
        AnyOneOf<String, Character, Placeholder> c = this.sOpt.get(this.sOpt.size()-1);
        if (val.isLeft()) {
            return c.isLeft() && c.getLeft().endsWith(val.getLeft());
        } else if (val.isRight()) {
            return c.isMiddle() && c.getMiddle() == val.get();
        }
        return false;
    }

    public byte[] getBytes() {
        return this.toString().getBytes(Charset.defaultCharset());
    }

    public boolean containsSpecial() {
        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isMiddle() && (sOptElem.getMiddle() == SpecialChars.ESCAPE_CHAR || sOptElem.getMiddle() == SpecialChars.WILDCARD_MULTI
                || sOptElem.getMiddle() == SpecialChars.WILDCARD_SINGLE)) {
                return true;
            }
        }
        return false;
    }

    public boolean containsWildcard() {
        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isMiddle() && (sOptElem.getMiddle() == SpecialChars.WILDCARD_MULTI
                    || sOptElem.getMiddle() == SpecialChars.WILDCARD_SINGLE)) {
                return true;
            }
        }
        return false;
    }

    public String convert(String escapeChar, String wildcardMulti, String wildcardSingle, String addEscaped, String addReserved, String filterChars) throws SigmaValueError {
        StringBuilder s = new StringBuilder();
        Set<Character> escapedChars = new HashSet<>();

        if (wildcardMulti != null) {
            for (Character c: wildcardMulti.toCharArray()) {
                escapedChars.add(c);
            }
        }
        if (wildcardSingle != null) {
            for (Character c: wildcardSingle.toCharArray()) {
                escapedChars.add(c);
            }
        }
        if (addEscaped != null) {
            for (Character c: addEscaped.toCharArray()) {
                escapedChars.add(c);
            }
        }

        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isLeft()) {
                if (Arrays.stream(addReserved.split(" ")).anyMatch(s1 -> s1.equals(sOptElem.getLeft()))) {
                    s.append(escapeChar);
                    s.append(sOptElem.getLeft());
                } else {
                    for (Character c : sOptElem.getLeft().toCharArray()) {
                        if (filterChars.contains(String.valueOf(c))) {
                            continue;
                        }
                        if (escapedChars.contains(c)) {
                            s.append(escapeChar);
                        }
                        s.append(c);
                    }
                }
            } else if (sOptElem.getMiddle() != null) {
                Character c = sOptElem.getMiddle();
                if (c == SpecialChars.WILDCARD_MULTI) {
                    if (wildcardMulti != null) {
                        s.append(wildcardMulti);
                    } else {
                        throw new SigmaValueError("Multi-character wildcard not specified for conversion");
                    }
                } else if (c == SpecialChars.WILDCARD_SINGLE) {
                    if (wildcardSingle != null) {
                        s.append(wildcardSingle);
                    } else {
                        throw new SigmaValueError("Single-character wildcard not specified for conversion");
                    }
                }
            }
        }
        return s.toString().replace(" ", "_ws_");
    }

    public SigmaString replaceWithPlaceholder(Pattern regex, String placeholderName) {
        List<AnyOneOf<String, Character, Placeholder>> result = new ArrayList<>();

        for (AnyOneOf<String, Character, Placeholder> elem: this.sOpt) {
            if (elem.isLeft()) {
                String elemStr = elem.getLeft();
                boolean matched = false;

                int idx = 0;
                Matcher matcher = regex.matcher(elemStr);
                while (matcher.find()) {
                    matched = true;

                    String sElem = elemStr.substring(idx, matcher.start());
                    if (!sElem.isEmpty()) {
                        result.add(AnyOneOf.leftVal(sElem));
                    }
                    result.add(AnyOneOf.rightVal(new Placeholder(placeholderName)));
                    idx = matcher.end();
                }

                if (matched) {
                    String sElem = elemStr.substring(idx);
                    if (!sElem.isEmpty()) {
                        result.add(AnyOneOf.leftVal(sElem));
                    }
                } else {
                    result.add(elem);
                }
            } else {
                result.add(elem);
            }
        }

        SigmaString sStr = new SigmaString(null);
        sStr.setsOpt(result);
        return sStr;
    }

    public boolean containsPlaceholder(List<String> include, List<String> exclude) {
        for (AnyOneOf<String, Character, Placeholder> elem: this.sOpt) {
            if (elem.isRight() && (include == null || include.contains(elem.get().getName())) &&
                    (exclude == null || !exclude.contains(elem.get().getName()))) {
                return true;
            }
        }
        return false;
    }

    public List<SigmaString> replacePlaceholders(Function<Placeholder, List<AnyOneOf<String, Character, Placeholder>>> callback) {
        if (!this.containsPlaceholder(null, null)) {
            return List.of(this);
        }

        List<SigmaString> results = new ArrayList<>();
        List<AnyOneOf<String, Character, Placeholder>> s = this.getsOpt();
        int size = s.size();
        for (int idx = 0; idx < size; ++idx) {
            if (s.get(idx).isRight()) {
                SigmaString prefix = new SigmaString(null);

                List<AnyOneOf<String, Character, Placeholder>> presOpt = new ArrayList<>();
                for (int preIdx = 0; preIdx < idx; ++preIdx) {
                    presOpt.add(s.get(preIdx));
                }
                prefix.setsOpt(presOpt);

                Placeholder placeholder = s.get(idx).get();

                SigmaString suffix = new SigmaString(null);

                List<AnyOneOf<String, Character, Placeholder>> sufsOpt = new ArrayList<>();
                for (int sufIdx = idx + 1; sufIdx < size; ++sufIdx) {
                    sufsOpt.add(s.get(sufIdx));
                }
                suffix.setsOpt(sufsOpt);

                for (SigmaString resultSuffix: suffix.replacePlaceholders(callback)) {
                    for (AnyOneOf<String, Character, Placeholder> replacement: callback.apply(placeholder)) {
                        SigmaString tempSuffix = new SigmaString(null);
                        tempSuffix.setsOpt(resultSuffix.getsOpt());

                        tempSuffix.prepend(replacement);
                        prefix.getsOpt().forEach(tempSuffix::prepend);
                        results.add(tempSuffix);
                    }
                }
                return results;
            }
        }
        return results;
    }

    public List<AnyOneOf<String, Character, Placeholder>> getsOpt() {
        return sOpt;
    }

    public void setsOpt(List<AnyOneOf<String, Character, Placeholder>> sOpt) {
        this.sOpt = new ArrayList<>();
        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isLeft()) {
                this.sOpt.add(AnyOneOf.leftVal(sOptElem.getLeft()));
            } else if (sOptElem.isMiddle()) {
                this.sOpt.add(AnyOneOf.middleVal(sOptElem.getMiddle()));
            } else {
                this.sOpt.add(AnyOneOf.rightVal(sOptElem.get()));
            }
        }
    }

    public String getOriginal() {
        return original;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaString that = (SigmaString) o;

        if (sOpt.size() != that.sOpt.size()) {
            return false;
        }

        for (int idx = 0; idx < sOpt.size(); ++idx) {
            if ((sOpt.get(idx).isLeft() && !that.sOpt.get(idx).isLeft()) ||
                    (sOpt.get(idx).isMiddle() && !that.sOpt.get(idx).isMiddle()) ||
                    (sOpt.get(idx).isRight() && !that.sOpt.get(idx).isRight())) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (AnyOneOf<String, Character, Placeholder> sOptElem: sOpt) {
            if (sOptElem.isLeft()) {
                sb.append(sOptElem.getLeft());
            } else if (sOptElem.isMiddle()) {
                sb.append(sOptElem.getMiddle());
            }
        }
        return sb.toString().replace(" ", "_ws_");
    }
}
