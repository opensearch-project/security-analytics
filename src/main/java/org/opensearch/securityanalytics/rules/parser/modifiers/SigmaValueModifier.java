/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.parser.modifiers;

import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.List;

public abstract class SigmaValueModifier extends SigmaModifier {

    public SigmaValueModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    public abstract Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError, SigmaRegularExpressionError, SigmaTypeError;
}