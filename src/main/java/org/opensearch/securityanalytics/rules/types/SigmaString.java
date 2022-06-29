/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.nio.charset.Charset;
import java.util.*;

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

    public String convert(String escapeChar, String wildcardMulti, String wildcardSingle, String addEscaped, String filterChars) throws SigmaValueError {
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
                for (Character c: sOptElem.getLeft().toCharArray()) {
                    if (filterChars.contains(String.valueOf(c))) {
                        continue;
                    }
                    if (escapedChars.contains(c)) {
                        s.append(escapeChar);
                    }
                    s.append(c);
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
        return s.toString();
    }

    public List<AnyOneOf<String, Character, Placeholder>> getsOpt() {
        return sOpt;
    }

    public void setsOpt(List<AnyOneOf<String, Character, Placeholder>> sOpt) {
        this.sOpt = sOpt;
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
        return sb.toString();
    }
}