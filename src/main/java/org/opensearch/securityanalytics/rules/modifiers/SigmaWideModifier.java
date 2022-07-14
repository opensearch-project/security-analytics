/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.Placeholder;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SigmaWideModifier extends SigmaValueModifier {

    public SigmaWideModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(SigmaString.class, null);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) {
        if (val.isLeft() && val.getLeft() instanceof SigmaString) {
            List<AnyOneOf<String, Character, Placeholder>> r = new ArrayList<>();

            for (AnyOneOf<String, Character, Placeholder> sOptElem: ((SigmaString) val.getLeft()).getsOpt()) {
                if (sOptElem.isLeft()) {
                    r.add(AnyOneOf.leftVal(new String(sOptElem.getLeft().getBytes(StandardCharsets.UTF_16LE), StandardCharsets.UTF_8)));
                } else{
                    r.add(sOptElem);
                }
            }

            SigmaString s = new SigmaString("");
            s.setsOpt(r);
            return Either.left(s);
        }
        return null;
    }
}