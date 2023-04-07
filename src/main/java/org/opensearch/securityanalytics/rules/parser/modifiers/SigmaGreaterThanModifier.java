/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.parser.modifiers;

import org.opensearch.securityanalytics.rules.parser.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.parser.types.SigmaCompareExpression;

import java.util.List;

public class SigmaGreaterThanModifier extends SigmaCompareModifier {

    public SigmaGreaterThanModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
        this.setOp(SigmaCompareExpression.CompareOperators.GT);
    }
}