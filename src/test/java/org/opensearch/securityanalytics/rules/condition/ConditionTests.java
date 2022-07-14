/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaDetection;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConditionTests extends OpenSearchTestCase {

    public void testOR() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("detection1 or detection2", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertEquals("val1", conditionItem.getArgs().get(0).getLeft().get().getValue().toString());
        Assert.assertEquals("val2", conditionItem.getArgs().get(1).getLeft().get().getValue().toString());
    }

    public void testAND() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("detection1 and detection2", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionAND.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertEquals("val1", conditionItem.getArgs().get(0).getLeft().get().getValue().toString());
        Assert.assertEquals("val2", conditionItem.getArgs().get(1).getLeft().get().getValue().toString());
    }

    public void testNOT() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("not detection1", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionNOT.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertEquals("val1", conditionItem.getArgs().get(0).getLeft().get().getValue().toString());
    }

    public void test4OR() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("detection1 or detection2 or detection4 or detection5", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isLeft());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(0).getLeft().isLeft() && conditionItem.getArgs().get(0).getLeft().getLeft().getArgs().size() == 2);
    }

    public void testSelector1() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("1 of detection*", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
    }

    public void testSelector1OfThem() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("1 of them", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(4).isLeft() && conditionItem.getArgs().get(4).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()));
    }

    public void testSelectorAny() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("any of detection*", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
    }

    public void testSelectorAnyfThem() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("any of them", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(4).isLeft() && conditionItem.getArgs().get(4).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()));
    }

    public void testSelectorAll() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("all of detection*", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionAND.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
    }

    public void testSelectorAllOfThem() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("all of them", sigmaSimpleDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionAND.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(2).isLeft() && conditionItem.getArgs().get(2).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(3).isLeft() && conditionItem.getArgs().get(3).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(4).isLeft() && conditionItem.getArgs().get(4).getLeft().isRight());
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(0).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(1).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(2).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(3).getLeft().get().getValue().toString()));
        Assert.assertTrue("val1".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val2".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val4".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "val5".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()) ||
                "other".equals(conditionItem.getArgs().get(4).getLeft().get().getValue().toString()));
    }

    public void testKeywordDetection() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("keywords", sigmaDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isRight());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isRight());
        Assert.assertEquals("keyword1", conditionItem.getArgs().get(0).getLeft().get().getValue().toString());
        Assert.assertEquals("123", conditionItem.getArgs().get(1).getLeft().get().getValue().toString());
    }

    public void testMultipleKeywordsDetection() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("keyword-list", sigmaDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionAND.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isLeft() &&
                conditionItem.getArgs().get(0).getLeft().getLeft() instanceof ConditionOR);
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isLeft() &&
                conditionItem.getArgs().get(1).getLeft().getLeft() instanceof ConditionOR);
        Assert.assertEquals("keyword1", conditionItem.getArgs().get(0).getLeft().getLeft().getArgs().get(0).getLeft().get().getValue().toString());
        Assert.assertEquals("keyword2", conditionItem.getArgs().get(0).getLeft().getLeft().getArgs().get(1).getLeft().get().getValue().toString());
        Assert.assertEquals("keyword4", conditionItem.getArgs().get(1).getLeft().getLeft().getArgs().get(0).getLeft().get().getValue().toString());
        Assert.assertEquals("keyword5", conditionItem.getArgs().get(1).getLeft().getLeft().getArgs().get(1).getLeft().get().getValue().toString());
    }

    public void testFieldValueListWithWildcardsDetection() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("field-valuelist-wildcards", sigmaDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionOR.class, conditionItem.getClass());
        Assert.assertTrue(conditionItem.getArgs().get(0).isLeft() && conditionItem.getArgs().get(0).getLeft().isMiddle());
        Assert.assertTrue(conditionItem.getArgs().get(1).isLeft() && conditionItem.getArgs().get(1).getLeft().isMiddle());
        Assert.assertEquals("field", conditionItem.getArgs().get(0).getLeft().getMiddle().getField());
        Assert.assertEquals("field", conditionItem.getArgs().get(1).getLeft().getMiddle().getField());
        Assert.assertEquals("simple-value", conditionItem.getArgs().get(0).getLeft().getMiddle().getValue().toString());
        Assert.assertEquals("*wildcards*", conditionItem.getArgs().get(1).getLeft().getMiddle().getValue().toString());
    }

    public void testEmptyFieldDetection() throws SigmaError {
        SigmaCondition sigmaCondition = new SigmaCondition("empty-field", sigmaDetections());
        ConditionItem conditionItem = sigmaCondition.parsed();
        Assert.assertEquals(ConditionFieldEqualsValueExpression.class, conditionItem.getClass());
        Assert.assertTrue(((ConditionFieldEqualsValueExpression) conditionItem).getValue() instanceof SigmaNull);
    }

    public void testUndefinedIdentifier() {
        Exception exception = assertThrows(SigmaConditionError.class, () -> {
            new SigmaCondition("detection", sigmaSimpleDetections()).parsed();
        });

        String expectedMessage = "Detection 'detection' not defined in detections";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testNullKeyword() {
        Exception exception = assertThrows(SigmaConditionError.class, () -> {
            new SigmaCondition("null-keyword", sigmaInvalidDetections()).parsed();
        });

        String expectedMessage = "Null value must be bound to a field";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    private SigmaDetections sigmaSimpleDetections() throws SigmaError {
        Map<String, SigmaDetection> detections = new HashMap<>();

        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("val1")), null, null, false);
        SigmaDetection detection1 = new SigmaDetection(List.of(Either.left(detectionItem1)), null);

        detections.put("detection1", detection1);

        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("val2")), null, null, false);
        SigmaDetection detection2 = new SigmaDetection(List.of(Either.left(detectionItem2)), null);

        detections.put("detection2", detection2);

        SigmaDetectionItem detectionItem4 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("val4")), null, null, false);
        SigmaDetection detection4 = new SigmaDetection(List.of(Either.left(detectionItem4)), null);

        detections.put("detection4", detection4);

        SigmaDetectionItem detectionItem5 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("val5")), null, null, false);
        SigmaDetection detection5 = new SigmaDetection(List.of(Either.left(detectionItem5)), null);

        detections.put("detection5", detection5);

        SigmaDetectionItem otherItem = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("other")), null, null, false);
        SigmaDetection other = new SigmaDetection(List.of(Either.left(otherItem)), null);

        detections.put("other", other);

        return new SigmaDetections(detections, Collections.emptyList());
    }

    private SigmaDetections sigmaDetections() throws SigmaError {
        Map<String, SigmaDetection> detections = new HashMap<>();

        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("keyword1"), new SigmaNumber(123)), null, null, false);
        SigmaDetection detection1 = new SigmaDetection(List.of(Either.left(detectionItem1)), null);

        detections.put("keywords", detection1);

        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("keyword1"), new SigmaString("keyword2")), null, null, false);
        SigmaDetectionItem detectionItem4 = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("keyword4"), new SigmaString("keyword5")), null, null, false);
        SigmaDetection detection2 = new SigmaDetection(List.of(Either.left(detectionItem2), Either.left(detectionItem4)), null);

        detections.put("keyword-list", detection2);

        SigmaDetectionItem detectionItem5 = new SigmaDetectionItem("field1", Collections.emptyList(),
                List.of(new SigmaString("value1")), null, null, false);
        SigmaDetectionItem detectionItem6 = new SigmaDetectionItem("field2", Collections.emptyList(),
                List.of(new SigmaNumber(123)), null, null, false);
        SigmaDetectionItem detectionItem7 = new SigmaDetectionItem("field3", Collections.emptyList(),
                List.of(new SigmaNull()), null, null, false);
        SigmaDetection detection4 = new SigmaDetection(List.of(Either.left(detectionItem5), Either.left(detectionItem6), Either.left(detectionItem7)), null);

        detections.put("field-value", detection4);

        SigmaDetectionItem detectionItem8 = new SigmaDetectionItem("field1", Collections.emptyList(),
                List.of(new SigmaString("value1-1"), new SigmaNumber(123)), null, null, false);
        SigmaDetectionItem detectionItem9 = new SigmaDetectionItem("field2", Collections.emptyList(),
                List.of(new SigmaString("value2-1"), new SigmaNumber(234)), null, null, false);
        SigmaDetection detection5 = new SigmaDetection(List.of(Either.left(detectionItem8), Either.left(detectionItem9)), null);

        detections.put("field-valuelist", detection5);

        SigmaDetectionItem detectionItem10 = new SigmaDetectionItem("field", Collections.emptyList(),
                List.of(new SigmaString("simple-value"), new SigmaString("*wildcards*")), null, null, false);
        SigmaDetection detection6 = new SigmaDetection(List.of(Either.left(detectionItem10)), null);

        detections.put("field-valuelist-wildcards", detection6);

        SigmaDetectionItem detectionItem11 = new SigmaDetectionItem("field", Collections.emptyList(),
                List.of(), null, null, false);
        SigmaDetection detection7 = new SigmaDetection(List.of(Either.left(detectionItem11)), null);

        detections.put("empty-field", detection7);
        return new SigmaDetections(detections, Collections.emptyList());
    }

    private SigmaDetections sigmaInvalidDetections() throws SigmaError {
        Map<String, SigmaDetection> detections = new HashMap<>();

        SigmaDetectionItem detectionItem = new SigmaDetectionItem(null, Collections.emptyList(),
                Collections.emptyList(), null, null, false);
        SigmaDetection detection = new SigmaDetection(List.of(Either.left(detectionItem)), null);

        detections.put("null-keyword", detection);
        return new SigmaDetections(detections, Collections.emptyList());
    }
}