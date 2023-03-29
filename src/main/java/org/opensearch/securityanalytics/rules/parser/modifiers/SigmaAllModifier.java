/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.parser.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.parser.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.parser.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.ArrayList;
import java.util.List;

public class SigmaAllModifier extends SigmaListModifier {

    public SigmaAllModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(ArrayList.class, null);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) {
        this.getDetectionItem().setValueLinking(Either.left(ConditionAND.class));
        return val;
    }
}