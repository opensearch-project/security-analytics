/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;


import java.util.ArrayList;
import java.util.List;

public class ConditionItem {

    private int argCount;
    private boolean tokenList;
    private List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args;

    private Either<ConditionItem, SigmaDetectionItem> parent;
    private boolean operator;

    public ConditionItem(int argCount, boolean tokenList,
                         List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        this.argCount = argCount;
        this.tokenList = tokenList;
        this.args = args;
    }

    public ConditionItem postProcess(SigmaDetections detections, Object parent) throws SigmaConditionError {
        this.parent = parent instanceof ConditionItem? Either.left((ConditionItem) parent): Either.right((SigmaDetectionItem) parent);

        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> newArgs = new ArrayList<>();
        for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: this.args) {
            if (arg.isLeft() && arg.getLeft().isLeft()) {
                newArgs.add(Either.left(AnyOneOf.leftVal(arg.getLeft().getLeft().postProcess(detections, parent))));
            } else if (arg.isLeft() && arg.getLeft().isMiddle()) {
                newArgs.add(Either.left(AnyOneOf.middleVal(arg.getLeft().getMiddle().postProcess(detections, parent))));
            } else if (arg.isLeft() && arg.getLeft().isRight()) {
                newArgs.add(Either.left(AnyOneOf.rightVal(arg.getLeft().get().postProcess(detections, parent))));
            }
        }
        this.args = newArgs;
        return this;
    }

    public void setParent(ConditionItem parent) {
        this.parent = Either.left(parent);
    }

    public List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> getArgs() {
        return args;
    }

    public void setArgs(List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        this.args = args;
    }
}