/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.List;

public abstract class SigmaListModifier extends SigmaModifier {


    public SigmaListModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    public abstract Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val);
}