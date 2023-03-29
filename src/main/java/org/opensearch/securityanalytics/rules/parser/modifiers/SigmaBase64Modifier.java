/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.parser.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.Base64;
import java.util.List;

public class SigmaBase64Modifier extends SigmaValueModifier {

    public SigmaBase64Modifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(SigmaString.class, null);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) throws SigmaValueError {
        if (val.isLeft() && val.getLeft() instanceof SigmaString) {
            if (((SigmaString) val.getLeft()).containsSpecial()) {
                throw new SigmaValueError("Base64 encoding of strings with wildcards is not allowed");
            }
            return Either.left(new SigmaString(Base64.getEncoder().encodeToString(((SigmaString) val.getLeft()).getBytes())));
        }
        return null;
    }
}