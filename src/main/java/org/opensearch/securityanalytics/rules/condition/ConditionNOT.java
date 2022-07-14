/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.condition;

import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public class ConditionNOT extends ConditionItem {

    private int argCount;
    private boolean operator;

    public ConditionNOT(boolean tokenList,
                        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args) {
        super(1, tokenList, args);
        this.argCount = 1;
        this.operator = true;
    }
}