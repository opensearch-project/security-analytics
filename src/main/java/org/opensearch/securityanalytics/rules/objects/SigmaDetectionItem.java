/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.modifiers.SigmaListModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaModifierFacade;
import org.opensearch.securityanalytics.rules.modifiers.SigmaValueModifier;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.types.SigmaTypeFacade;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SigmaDetectionItem {

    private String field;

    private List<Class<? extends SigmaModifier>> modifiers;

    private List<SigmaType> value;

    private Either<Class<ConditionAND>, Class<ConditionOR>> valueLinking;

    private SigmaType originalValue;

    private boolean autoModifiers;

    private SigmaDetection parent;

    public SigmaDetectionItem(String field, List<Class<? extends SigmaModifier>> modifiers, List<SigmaType> value,
                              Either<Class<ConditionAND>, Class<ConditionOR>> valueLinking, SigmaType originalValue, boolean autoModifiers) throws SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        this.field = field;
        this.modifiers = modifiers;
        this.value = value;
        this.valueLinking = valueLinking != null? valueLinking: Either.right(ConditionOR.class);
        this.originalValue = originalValue;
        this.autoModifiers = autoModifiers;

        if (autoModifiers) {
            this.applyModifiers();
        }
    }

    private void applyModifiers() throws SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        List<Class<? extends SigmaModifier>> appliedModifiers = new ArrayList<>();

        for (Class<? extends SigmaModifier> modifier: modifiers) {
            SigmaModifier modifierInstance = SigmaModifierFacade.sigmaModifier(modifier, this, appliedModifiers);

            if (modifierInstance instanceof SigmaValueModifier) {
                List<SigmaType> appliedValue = new ArrayList<>();
                for (SigmaType val: this.value) {
                    appliedValue.addAll(modifierInstance.apply(Either.left(val)));
                }
                this.value = appliedValue;
            } else if (modifierInstance instanceof SigmaListModifier) {
                this.value = modifierInstance.apply(Either.right(this.value));
            } else {
                throw new IllegalArgumentException("Instance of SigmaValueModifier or SigmaListModifier was expected");
            }
            appliedModifiers.add(modifier);
        }
    }

    public static <T> SigmaDetectionItem fromMapping(String key, Either<T, List<T>> val) throws SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        String field = null;
        List<String> modifierIds = new ArrayList<>();
        if (key != null) {
            String[] tokens = key.split("\\|");
            if (tokens.length > 0) {
                field = tokens[0].isEmpty()? null: tokens[0];
                modifierIds = Arrays.stream(tokens).skip(1).collect(Collectors.toList());
            }
        }

        List<Class<? extends SigmaModifier>> modifiers = new ArrayList<>();
        for (String modId: modifierIds) {
            Class<? extends SigmaModifier> modifier = SigmaModifierFacade.getModifier(modId);
            if (modifier != null) {
                modifiers.add(modifier);
            } else {
                throw new SigmaModifierError("Unknown modifier " + modId);
            }
        }

        List<T> values = new ArrayList<>();
        if (val != null && val.isLeft()) {
            values.add(val.getLeft());
        } else if (val != null && val.isRight()) {
            values.addAll(val.get());
        } else {
            values.add(null);
        }

        List<SigmaType> sigmaTypes = new ArrayList<>();
        for (T v: values) {
            sigmaTypes.add(SigmaTypeFacade.sigmaType(v));
        }

        return new SigmaDetectionItem(field, modifiers, sigmaTypes, null, null, true);
    }

    public static <T> SigmaDetectionItem fromValue(Either<T, List<T>> val) throws SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        return SigmaDetectionItem.fromMapping(null, val);
    }

    public Either<Either<ConditionAND, ConditionOR>, Either<ConditionFieldEqualsValueExpression, ConditionValueExpression>> postProcess(SigmaDetections detections, Object parent) throws SigmaConditionError {
        this.parent = (SigmaDetection) parent;

        if (this.value.size() == 0) {
            if (this.field == null) {
                throw new SigmaConditionError("Null value must be bound to a field");
            } else {
                return Either.right(Either.left(new ConditionFieldEqualsValueExpression(field, new SigmaNull()).postProcess(detections, this)));
            }
        }
        if (this.value.size() == 1) {
            if (this.field == null) {
                return Either.right(Either.right(new ConditionValueExpression(this.value.get(0)).postProcess(detections, this)));
            } else {
                return Either.right(Either.left(new ConditionFieldEqualsValueExpression(field, value.get(0)).postProcess(detections, this)));
            }
        } else {
            List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> valueExpressions = new ArrayList<>();
            if (this.field == null) {
                for (SigmaType v: value) {
                    valueExpressions.add(Either.left(AnyOneOf.rightVal(new ConditionValueExpression(v))));
                }

                if (valueLinking.isLeft()) {
                    ConditionAND conditionAND = new ConditionAND(false, valueExpressions);
                    conditionAND = (ConditionAND) conditionAND.postProcess(detections, this);
                    return Either.left(Either.left(conditionAND));
                } else if (valueLinking.isRight()) {
                    ConditionOR conditionOR = new ConditionOR(false, valueExpressions);
                    conditionOR = (ConditionOR) conditionOR.postProcess(detections, this);
                    return Either.left(Either.right(conditionOR));
                }
            } else {
                for (SigmaType v: value) {
                    valueExpressions.add(Either.left(AnyOneOf.middleVal(new ConditionFieldEqualsValueExpression(field, v))));
                }

                if (valueLinking.isLeft()) {
                    ConditionAND conditionAND = new ConditionAND(false, valueExpressions);
                    conditionAND = (ConditionAND) conditionAND.postProcess(detections, this);
                    return Either.left(Either.left(conditionAND));
                } else if (valueLinking.isRight()) {
                    ConditionOR conditionOR = new ConditionOR(false, valueExpressions);
                    conditionOR = (ConditionOR) conditionOR.postProcess(detections, this);
                    return Either.left(Either.right(conditionOR));
                }
            }
        }
        return null;
    }

    public boolean isKeyword() {
        return field == null;
    }

    public String getField() {
        return field;
    }

    public List<SigmaType> getValue() {
        return value;
    }

    public List<Class<? extends SigmaModifier>> getModifiers() {
        return modifiers;
    }

    public Either<Class<ConditionAND>, Class<ConditionOR>> getValueLinking() {
        return valueLinking;
    }

    public void setValueLinking(Either<Class<ConditionAND>, Class<ConditionOR>> valueLinking) {
        this.valueLinking = valueLinking;
    }
}