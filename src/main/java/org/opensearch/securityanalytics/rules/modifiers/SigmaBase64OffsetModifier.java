/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.apache.commons.lang3.ArrayUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class SigmaBase64OffsetModifier extends SigmaValueModifier {

    private List<Integer> startOffsets;
    private List<Integer> endOffsets;

    public SigmaBase64OffsetModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
        this.startOffsets = Arrays.asList(0, 2, 3);
        this.endOffsets = Arrays.asList(0, -3, -2);
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

            List<SigmaType> values = new ArrayList<>();
            for (int i = 0; i < 3; ++i) {
                byte[] valBytes = ((SigmaString) val.getLeft()).getBytes();

                for (int j = 0; j < i; ++j) {
                    valBytes = ArrayUtils.insert(0, valBytes, (byte) ' ');
                }
                String valB64Encode = Base64.getEncoder().encodeToString(valBytes);
                valB64Encode = valB64Encode.substring(startOffsets.get(i), valB64Encode.length() + endOffsets.get((((SigmaString) val.getLeft()).length() + i) % 3));
                values.add(new SigmaString(valB64Encode));
            }

            return Either.left(new SigmaExpansion(values));
        }
        return null;
    }
}