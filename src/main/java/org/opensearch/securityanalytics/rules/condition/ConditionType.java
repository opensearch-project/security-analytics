/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

public class ConditionType {

    private Either<AnyOneOf<ConditionAND, ConditionOR, ConditionNOT>, Either<ConditionFieldEqualsValueExpression, ConditionValueExpression>> condition;

    public ConditionType(Either<AnyOneOf<ConditionAND, ConditionOR, ConditionNOT>, Either<ConditionFieldEqualsValueExpression, ConditionValueExpression>> condition) {
        this.condition = condition;
    }

    public ConditionAND getConditionAND() {
        return this.condition.getLeft().getLeft();
    }

    public boolean isConditionAND() {
        return this.condition.isLeft() && this.condition.getLeft().isLeft();
    }

    public ConditionOR getConditionOR() {
        return this.condition.getLeft().getMiddle();
    }

    public boolean isConditionOR() {
        return this.condition.isLeft() && this.condition.getLeft().isMiddle();
    }

    public ConditionNOT getConditionNOT() {
        return this.condition.getLeft().get();
    }

    public boolean isConditionNOT() {
        return this.condition.isLeft() && this.condition.getLeft().isRight();
    }

    public ConditionFieldEqualsValueExpression getEqualsValueExpression() {
        return this.condition.get().getLeft();
    }

    public boolean isEqualsValueExpression() {
        return this.condition.isRight() && this.condition.get().isLeft();
    }

    public ConditionValueExpression getValueExpression() {
        return this.condition.get().get();
    }

    public boolean isValueExpression() {
        return this.condition.isRight() && this.condition.get().isRight();
    }

    public Class<?> getClazz() {
        if (this.condition.isLeft() && this.condition.getLeft().isLeft()) {
            return ConditionAND.class;
        } else if (this.condition.isLeft() && this.condition.getLeft().isMiddle()) {
            return ConditionOR.class;
        } else if (this.condition.isLeft() && this.condition.getLeft().isRight()) {
            return ConditionNOT.class;
        } else if (this.condition.isRight() && this.condition.get().isLeft()) {
            return ConditionFieldEqualsValueExpression.class;
        } else {
            return ConditionValueExpression.class;
        }
    }
}