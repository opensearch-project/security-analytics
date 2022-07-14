/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetection;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public class ConditionIdentifier extends ConditionItem {

    private int argCount;
    private boolean tokenList;
    private String identifier;

    public ConditionIdentifier(List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        super(1, true, args);
        this.argCount = 1;
        this.tokenList = true;
        this.identifier = args.get(0).get();
    }

    public ConditionItem postProcess(SigmaDetections detections, Object parent) throws SigmaConditionError {
        this.setParent((ConditionItem) parent);

        if (detections.getDetections().containsKey(this.identifier)) {
            SigmaDetection detection = detections.getDetections().get(this.identifier);
            AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression> item = detection.postProcess(detections, this);
            return item.isLeft()? item.getLeft(): (item.isMiddle()? item.getMiddle(): item.get());
        } else {
            throw new SigmaConditionError("Detection '" + this.identifier + "' not defined in detections");
        }
    }
}