/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaCIDRModifierTests extends SigmaModifierTests {

    public void testCidr() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/24")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("192.168.1.0/24", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv4NoPrefix() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.1")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("192.168.1.1", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/32")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("2001:db8::/32", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6Loopback() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("::1/128")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("::1/128", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6NoPrefix() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("fe80::1")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("fe80::1", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6InvalidPrefix() {
        Exception exception = assertThrows(SigmaTypeError.class, () -> {
            new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/129")));
        });

        String expectedMessage = "Invalid CIDR expression";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testCidrIPv4TrailingSlash() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/"))));
    }

    public void testCidrIPv6TrailingSlash() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/"))));
    }

    public void testCidrEmptyString() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString(""))));
    }

    public void testCidrRejectsSignedPrefix() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/+24"))));
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/+32"))));
    }

    public void testCidrRejectsWhitespaceInPrefix() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/24 "))));
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/ 32"))));
    }

    public void testCidrIPv4CanonicalNetwork() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("10.0.0.0/8")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("10.0.0.0/8", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv4RejectsHostBits() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.5/24"))));
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.31/27"))));
    }

    public void testCidrIPv6RejectsHostBits() {
        assertThrows(SigmaTypeError.class, () ->
                new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::1/32"))));
    }

    public void testCidrPrefixZero() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("0.0.0.0/0")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("0.0.0.0/0", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrWithOther() {
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            new SigmaCIDRModifier(dummyDetectionItem(), List.of(SigmaBase64Modifier.class)).apply(Either.left(new SigmaString("192.168.1.0/24")));
        });

        String expectedMessage = "CIDR expression modifier only applicable to unmodified values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}
