/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;

public class SigmaDetectionTests extends OpenSearchTestCase {

    public void testSigmaDetectionItems() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError, SigmaDetectionError {
        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem("key_1", Collections.emptyList(),
                List.of(new SigmaString("value_1")), null, null, false);
        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem("key_2", Collections.emptyList(),
                List.of(new SigmaString("value_2")), null, null, false);

        SigmaDetection detection = new SigmaDetection(List.of(Either.left(detectionItem1), Either.left(detectionItem2)), null);
        Assert.assertTrue(detection.getItemLinking().isLeft());
    }

    public void testSigmaDetectionDetections() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError, SigmaDetectionError {
        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem("key_1", Collections.emptyList(),
                List.of(new SigmaString("value_1")), null, null, false);
        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem("key_2", Collections.emptyList(),
                List.of(new SigmaString("value_2")), null, null, false);

        SigmaDetection detection1 = new SigmaDetection(List.of(Either.left(detectionItem1)), null);
        SigmaDetection detection2 = new SigmaDetection(List.of(Either.left(detectionItem2)), null);

        SigmaDetection detection = new SigmaDetection(List.of(Either.right(detection1), Either.right(detection2)), null);
        Assert.assertTrue(detection.getItemLinking().isRight());
    }

    public void testSigmaDetectionMixed() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError, SigmaDetectionError {
        SigmaDetectionItem detectionItem1 = new SigmaDetectionItem("key_1", Collections.emptyList(),
                List.of(new SigmaString("value_1")), null, null, false);
        SigmaDetectionItem detectionItem2 = new SigmaDetectionItem("key_2", Collections.emptyList(),
                List.of(new SigmaString("value_2")), null, null, false);

        SigmaDetection detection2 = new SigmaDetection(List.of(Either.left(detectionItem2)), null);

        SigmaDetection detection = new SigmaDetection(List.of(Either.left(detectionItem1), Either.right(detection2)), null);
        Assert.assertTrue(detection.getItemLinking().isLeft());
    }
}