/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.nio.charset.Charset;
import java.util.List;

import static org.opensearch.securityanalytics.rules.types.SigmaString.SpecialChars.WILDCARD_MULTI;
import static org.opensearch.securityanalytics.rules.types.SigmaString.SpecialChars.WILDCARD_SINGLE;

public class SigmaStringTests extends OpenSearchTestCase {

    public void testStringsEmpty() {
        SigmaString s = new SigmaString(null);
        Assert.assertTrue(s.getsOpt().isEmpty());
    }

    public void testStringsPlain() {
        SigmaString s = new SigmaString("plain");
        Assert.assertEquals(1, s.getsOpt().size());
        Assert.assertEquals("plain", s.getsOpt().get(0).getLeft());
    }

    public void testStringsMerge() {
        SigmaString s = new SigmaString(null);
        s.setsOpt(List.of(AnyOneOf.middleVal(WILDCARD_MULTI), AnyOneOf.leftVal("te"),
                AnyOneOf.leftVal("st"), AnyOneOf.middleVal(WILDCARD_MULTI)));
        s.mergeStrings();
        List<AnyOneOf<String, Character, Placeholder>> sOpt = s.getsOpt();
        Assert.assertEquals(3, sOpt.size());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(0).getMiddle().charValue());
        Assert.assertEquals("test", s.getsOpt().get(1).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(2).getMiddle().charValue());
    }

    public void testStringsMergeEnd() {
        SigmaString s = new SigmaString(null);
        s.setsOpt(List.of(AnyOneOf.middleVal(WILDCARD_MULTI), AnyOneOf.leftVal("test"),
                AnyOneOf.middleVal(WILDCARD_MULTI), AnyOneOf.leftVal("te"), AnyOneOf.leftVal("st"), AnyOneOf.leftVal("test")));
        s.mergeStrings();
        List<AnyOneOf<String, Character, Placeholder>> sOpt = s.getsOpt();
        Assert.assertEquals(4, sOpt.size());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(0).getMiddle().charValue());
        Assert.assertEquals("test", s.getsOpt().get(1).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(2).getMiddle().charValue());
        Assert.assertEquals("testtest", s.getsOpt().get(3).getLeft());
    }

    public void testStringsMergeStart() {
        SigmaString s = new SigmaString(null);
        s.setsOpt(List.of(AnyOneOf.leftVal("te"), AnyOneOf.leftVal("st"), AnyOneOf.leftVal("test"),
                AnyOneOf.middleVal(WILDCARD_MULTI), AnyOneOf.leftVal("test"), AnyOneOf.middleVal(WILDCARD_MULTI)));
        s.mergeStrings();
        List<AnyOneOf<String, Character, Placeholder>> sOpt = s.getsOpt();
        Assert.assertEquals(4, sOpt.size());
        Assert.assertEquals("testtest", s.getsOpt().get(0).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(1).getMiddle().charValue());
        Assert.assertEquals("test", s.getsOpt().get(2).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(3).getMiddle().charValue());
    }

    public void testStringsWildcards() {
        SigmaString s = new SigmaString("wild*cards?contained");
        Assert.assertEquals(5, s.getsOpt().size());
        Assert.assertEquals("wild", s.getsOpt().get(0).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(1).getMiddle().charValue());
        Assert.assertEquals("cards", s.getsOpt().get(2).getLeft());
        Assert.assertEquals(WILDCARD_SINGLE, s.getsOpt().get(3).getMiddle().charValue());
        Assert.assertEquals("contained", s.getsOpt().get(4).getLeft());
    }

    public void testStringsEscaping() {
        SigmaString s = new SigmaString("escaped\\*\\?\\\\*?");
        Assert.assertEquals(3, s.getsOpt().size());
        Assert.assertEquals("escaped*?\\", s.getsOpt().get(0).getLeft());
        Assert.assertEquals(WILDCARD_MULTI, s.getsOpt().get(1).getMiddle().charValue());
        Assert.assertEquals(WILDCARD_SINGLE, s.getsOpt().get(2).getMiddle().charValue());
    }

    public void testStringsEscapingNonSpecial() {
        SigmaString s = new SigmaString("escaped\\nonspecial");
        Assert.assertEquals(1, s.getsOpt().size());
        Assert.assertEquals("escaped\\nonspecial", s.getsOpt().get(0).getLeft());
    }

    public void testStringsEscapingEnd() {
        SigmaString s = new SigmaString("finalescape\\");
        Assert.assertEquals(1, s.getsOpt().size());
        Assert.assertEquals("finalescape\\", s.getsOpt().get(0).getLeft());
    }

    public void testStringsEqual() {
        SigmaString s1 = new SigmaString("test*string");
        SigmaString s2 = new SigmaString("test*string");
        Assert.assertEquals(s1, s2);
    }

    public void testStringsNotEqual() {
        SigmaString s1 = new SigmaString("test*string");
        SigmaString s2 = new SigmaString("test\\*string");
        Assert.assertNotEquals(s1, s2);
    }

    public void testStringsStartsWith() {
        SigmaString s = new SigmaString("foobar");
        Assert.assertTrue(s.startsWith(Either.left("foo")));
    }

    public void testStringsStartsWithSpecial() {
        SigmaString s = new SigmaString("*foobar");
        Assert.assertTrue(s.startsWith(Either.right(WILDCARD_MULTI)));
    }

    public void testStringsStartsWithDiffTypes() {
        SigmaString s = new SigmaString("*foobar");
        Assert.assertFalse(s.startsWith(Either.left("foo")));
    }

    public void testStringsEndsWith() {
        SigmaString s = new SigmaString("foobar");
        Assert.assertTrue(s.endsWith(Either.left("bar")));
    }

    public void testStringsEndsWithSpecial() {
        SigmaString s = new SigmaString("foobar*");
        Assert.assertTrue(s.endsWith(Either.right(WILDCARD_MULTI)));
    }

    public void testStringsEndsWithDiffTypes() {
        SigmaString s = new SigmaString("foobar*");
        Assert.assertFalse(s.startsWith(Either.left("bar")));
    }

    public void testStringsContainsSpecial() {
        SigmaString s = new SigmaString("foo*bar");
        Assert.assertTrue(s.containsSpecial());
    }

    public void testStringsNotContainsSpecial() {
        SigmaString s = new SigmaString("foobar");
        Assert.assertFalse(s.containsSpecial());
    }

    public void testStringsAddSigmaString() {
        SigmaString s = new SigmaString("*foo?");
        s = s.append(AnyOneOf.leftVal("bar*"));
        Assert.assertEquals("*foo?bar*", s.toString());
    }

    public void testStringsPrependSigmaString() {
        SigmaString s = new SigmaString("bar*");
        s = s.prepend(AnyOneOf.leftVal("*foo?"));
        Assert.assertEquals("*foo?bar*", s.toString());
    }

    public void testStringsAddLSpecial() {
        SigmaString s = new SigmaString("foo*");
        s = s.prepend(AnyOneOf.middleVal(WILDCARD_MULTI));
        Assert.assertEquals("*foo*", s.toString());
    }

    public void testStringsAddRSpecial() {
        SigmaString s = new SigmaString("*foo");
        s = s.append(AnyOneOf.middleVal(WILDCARD_MULTI));
        Assert.assertEquals("*foo*", s.toString());
    }

    public void testStringsToString() {
        SigmaString s = new SigmaString("test*?");
        Assert.assertEquals("test*?", s.toString());
    }

    public void testStringsToBytes() {
        SigmaString s = new SigmaString("test*?");
        Assert.assertArrayEquals("test*?".getBytes(Charset.defaultCharset()), s.getBytes());
    }

    public void testStringsLength() {
        Assert.assertEquals(14, sigmaString().length());
    }

    public void testStringsConvert() throws SigmaValueError {
        SigmaString s = new SigmaString("foo?\\*bar*");
        Assert.assertEquals("\\f?\\*bar*", s.convert("\\", "*", "?", "f", "o"));
    }

    public void testStringsConvertNoMultiWildcard() {
        assertThrows(SigmaValueError.class, () -> {
            SigmaString s = new SigmaString("foo*bar");
            s.convert("\\", null, "?", "f", "o");
        });
    }

    public void testStringsConvertNoSingleWildcard() {
        assertThrows(SigmaValueError.class, () -> {
            SigmaString s = new SigmaString("foo?bar");
            s.convert("\\", "*", null, "f", "o");
        });
    }

    private SigmaString sigmaString() {
        return new SigmaString("*Test*Str\\*ing*");
    }

    private SigmaString emptySigmaString() {
        return new SigmaString("");
    }
}