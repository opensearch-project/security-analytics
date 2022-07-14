/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.*;
import org.opensearch.securityanalytics.rules.modifiers.SigmaModifier;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SigmaModifierTests extends OpenSearchTestCase {

    public void testTypecheckPlain() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        Assert.assertTrue(dummyPlainModifier().typeCheck(Either.left(new SigmaString("foobar"))));
    }

    public void testTypecheckPlainWrong() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        Assert.assertFalse(dummyPlainModifier().typeCheck(Either.left(new SigmaNumber(123))));
    }

    public void testTypecheckPlainWrongApply() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        assertThrows(SigmaTypeError.class, () -> {
            dummyPlainModifier().apply(Either.left(new SigmaNumber(123)));
        });
    }

    public void testTypecheckApplyListInput() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        ArrayList<SigmaType> elements = new ArrayList<>();
        elements.add(new SigmaString("foobar"));
        List<SigmaType> values = dummySequenceModifier().apply(Either.right(elements));
        Assert.assertTrue(values.get(0) instanceof SigmaString && values.get(0).toString().equals(""));
    }

    public void testTypecheckUnion() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        Assert.assertTrue(dummyUnionModifier().typeCheck(Either.left(new SigmaString("foobar"))));
    }

    public void testTypecheckUnionWrong() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        Assert.assertFalse(dummyUnionModifier().typeCheck(Either.left(new SigmaRegularExpression(".*"))));
    }

    public void testTypecheckSequence() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        ArrayList<SigmaType> elements = new ArrayList<>();
        elements.add(new SigmaString("foobar"));
        Assert.assertTrue(dummySequenceModifier().typeCheck(Either.right(elements)));
    }

    public SigmaDetectionItem dummyDetectionItem() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        return new SigmaDetectionItem(null, Collections.emptyList(), List.of(new SigmaString("foobar")), null, null, false);
    }

    static class DummyPlainModifier extends SigmaModifier {

        public DummyPlainModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
            super(detectionItem, appliedModifiers);
        }

        @Override
        public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError, SigmaRegularExpressionError, SigmaTypeError {
            return Either.left(new SigmaString(""));
        }

        @Override
        public Pair<Class<?>, Class<?>> getTypeHints() {
            return Pair.of(SigmaString.class, null);
        }
    }

    static class DummyUnionModifier extends SigmaModifier {

        public DummyUnionModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
            super(detectionItem, appliedModifiers);
        }

        @Override
        public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError, SigmaRegularExpressionError, SigmaTypeError {
            return Either.left(new SigmaString(""));
        }

        @Override
        public Pair<Class<?>, Class<?>> getTypeHints() {
            return Pair.of(SigmaString.class, SigmaNumber.class);
        }
    }

    static class DummySequenceModifier extends SigmaModifier {

        public DummySequenceModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
            super(detectionItem, appliedModifiers);
        }

        @Override
        public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError, SigmaRegularExpressionError, SigmaTypeError {
            return Either.right(List.of(new SigmaString("")));
        }

        @Override
        public Pair<Class<?>, Class<?>> getTypeHints() {
            return Pair.of(ArrayList.class, null);
        }
    }

    private SigmaModifier dummyPlainModifier() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        return new DummyPlainModifier(dummyDetectionItem(), Collections.emptyList());
    }

    private SigmaModifier dummySequenceModifier() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        return new DummySequenceModifier(dummyDetectionItem(), Collections.emptyList());
    }

    private SigmaModifier dummyUnionModifier() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        return new DummyUnionModifier(dummyDetectionItem(), Collections.emptyList());
    }
}