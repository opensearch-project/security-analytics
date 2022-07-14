/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.objects.SigmaDetectionItem;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SigmaModifierFacade {

    private Map<String, Class<? extends SigmaModifier>> modifierMap;
    private static SigmaModifierFacade modifierFacade;

    public SigmaModifierFacade() {
        modifierMap = new HashMap<>();
        modifierMap.put("contains", SigmaContainsModifier.class);
        modifierMap.put("startswith", SigmaStartswithModifier.class);
        modifierMap.put("endswith", SigmaEndswithModifier.class);
        modifierMap.put("base64", SigmaBase64Modifier.class);
        modifierMap.put("base64offset", SigmaBase64OffsetModifier.class);
        modifierMap.put("wide", SigmaWideModifier.class);
        modifierMap.put("windash", SigmaWindowsDashModifier.class);
        modifierMap.put("re", SigmaRegularExpressionModifier.class);
        modifierMap.put("cidr", SigmaCIDRModifier.class);
        modifierMap.put("all", SigmaAllModifier.class);
        modifierMap.put("lt", SigmaLessThanModifier.class);
        modifierMap.put("lte", SigmaLessThanEqualModifier.class);
        modifierMap.put("gt", SigmaGreaterThanModifier.class);
        modifierMap.put("gte", SigmaGreaterThanEqualModifier.class);
    }

    public static SigmaModifier sigmaModifier(Class<? extends SigmaModifier> clazz, SigmaDetectionItem detectionItem,
                                              List<Class<? extends SigmaModifier>> appliedModifiers) throws SigmaModifierError {
        if (modifierFacade == null) {
            modifierFacade = new SigmaModifierFacade();
        }

        if (clazz.equals(SigmaContainsModifier.class)) {
            return new SigmaContainsModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaStartswithModifier.class)) {
            return new SigmaStartswithModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaEndswithModifier.class)) {
            return new SigmaEndswithModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaBase64Modifier.class)) {
            return new SigmaBase64Modifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaBase64OffsetModifier.class)) {
            return new SigmaBase64OffsetModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaWideModifier.class)) {
            return new SigmaWideModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaWindowsDashModifier.class)) {
            return new SigmaWindowsDashModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaRegularExpressionModifier.class)) {
            return new SigmaRegularExpressionModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaCIDRModifier.class)) {
            return new SigmaCIDRModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaAllModifier.class)) {
            return new SigmaAllModifier(detectionItem, appliedModifiers);
        }  else if (clazz.equals(SigmaLessThanModifier.class)) {
            return new SigmaLessThanModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaLessThanEqualModifier.class)) {
            return new SigmaLessThanEqualModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaGreaterThanModifier.class)) {
            return new SigmaGreaterThanModifier(detectionItem, appliedModifiers);
        } else if (clazz.equals(SigmaGreaterThanEqualModifier.class)) {
            return new SigmaGreaterThanEqualModifier(detectionItem, appliedModifiers);
        }
        throw new SigmaModifierError("modifier not found-" + clazz.getName());
    }

    public static Map<String, String> reverseModifierMapping() {
        if (modifierFacade == null) {
            modifierFacade = new SigmaModifierFacade();
        }

        Map<String, String> reverseModifierMap = new HashMap<>();
        for (Map.Entry<String, Class<? extends SigmaModifier>> modifier: modifierFacade.modifierMap.entrySet()) {
            reverseModifierMap.put(modifier.getValue().getName(), modifier.getKey());
        }

        return reverseModifierMap;
    }

    public static Class<? extends SigmaModifier> getModifier(String modifier) {
        if (modifierFacade == null) {
            modifierFacade = new SigmaModifierFacade();
        }
        return modifierFacade.modifierMap.get(modifier);
    }
}