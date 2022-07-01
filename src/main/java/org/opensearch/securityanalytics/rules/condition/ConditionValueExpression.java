/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;

public class ConditionValueExpression  extends ConditionItem {

    private SigmaType value;

    private Either<ConditionItem, SigmaDetectionItem> parent;

    public ConditionValueExpression(SigmaType value) {
        super(1, false, Collections.emptyList());
        this.value = value;
    }

    public ConditionValueExpression postProcess(SigmaDetections detections, Object parent) {
        this.parent = parent instanceof ConditionItem? Either.left((ConditionItem) parent): Either.right((SigmaDetectionItem) parent);
        return this;
    }

    public SigmaType getValue() {
        return value;
    }
}