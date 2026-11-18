/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;
import org.opensearch.securityanalytics.rules.types.Placeholder;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SigmaWindowsDashModifier extends SigmaValueModifier {

    public SigmaWindowsDashModifier(SigmaDetectionItem detectionItem, List<Class<? extends SigmaModifier>> appliedModifiers) {
        super(detectionItem, appliedModifiers);
    }

    @Override
    public Pair<Class<?>, Class<?>> getTypeHints() {
        return Pair.of(SigmaString.class, SigmaExpansion.class);
    }

    @Override
    public Either<SigmaType, List<SigmaType>> modify(Either<SigmaType, List<SigmaType>> val) {
        if (val.isLeft() && val.getLeft() instanceof SigmaString) {
            SigmaString value = ((SigmaString) val.getLeft())
                .replaceWithPlaceholder(Pattern.compile("\\B[-/]\\b"), "_windash");
            List<SigmaString> alternatives = List.of(new SigmaString(null));
            // Expand left-to-right on parsed segments: never reparse literal glob characters
            // or encode/decode spaces. Each branch owns its list, including with multiple flags.
            for (AnyOneOf<String, Character, Placeholder> part : value.getsOpt()) {
                List<SigmaString> next = new ArrayList<>();
                List<AnyOneOf<String, Character, Placeholder>> replacements = part.isRight()
                    && part.get().getName().equals("_windash")
                    ? List.of(AnyOneOf.leftVal("-"), AnyOneOf.leftVal("/")) : List.of(part);
                for (SigmaString prefix : alternatives) {
                    for (AnyOneOf<String, Character, Placeholder> replacement : replacements) {
                        SigmaString expanded = new SigmaString(null);
                        expanded.setsOpt(prefix.getsOpt());
                        expanded.append(replacement);
                        next.add(expanded);
                    }
                }
                alternatives = next;
            }
            return Either.left(new SigmaExpansion(new ArrayList<SigmaType>(alternatives)));
        }
        return null;
    }
}