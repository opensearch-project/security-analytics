/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionType;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.apache.commons.lang3.tuple.Pair;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class QueryBackend {
    private boolean convertOrAsIn;
    private boolean convertAndAsIn;
    private boolean collectErrors;
    protected boolean enableFieldMappings;
    private List<Pair<SigmaRule, SigmaError>> errors;
    protected Map<String, String> fieldMappings;

    private Map<String, Object> queryFields;
    protected Map<String, Object> ruleQueryFields;

    @SuppressWarnings("unchecked")
    public QueryBackend(Map<String, String> fieldMappings, boolean convertAndAsIn, boolean enableFieldMappings, boolean convertOrAsIn, boolean collectErrors) {
        this.convertAndAsIn = convertAndAsIn;
        this.convertOrAsIn = convertOrAsIn;
        this.collectErrors = collectErrors;
        this.enableFieldMappings = enableFieldMappings;
        this.errors = new ArrayList<>();
        this.queryFields = new HashMap<>();

        if (this.enableFieldMappings) {
            this.fieldMappings = fieldMappings;
        } else {
            this.fieldMappings = new HashMap<>();
        }
    }

    public List<Object> convertRule(SigmaRule rule) throws SigmaError {
        this.ruleQueryFields = new HashMap<>();
        List<Object> queries = new ArrayList<>();
        try {
            for (SigmaCondition condition: rule.getDetection().getParsedCondition()) {
                Pair<ConditionItem, AggregationItem> parsedItems = condition.parsed();
                ConditionItem conditionItem = parsedItems.getLeft();
                AggregationItem aggItem = parsedItems.getRight();

                Object query;
                if (conditionItem instanceof ConditionAND) {
                    query = this.convertCondition(new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) conditionItem))), false, false);
                } else if (conditionItem instanceof ConditionOR) {
                    query = this.convertCondition(new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) conditionItem))), false, false);
                } else if (conditionItem instanceof ConditionNOT) {
                    query = this.convertCondition(new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) conditionItem))), true, false);
                } else if (conditionItem instanceof ConditionFieldEqualsValueExpression) {
                    query = this.convertCondition(new ConditionType(Either.right(Either.left((ConditionFieldEqualsValueExpression) conditionItem))), false, false);
                } else {
                    query = this.convertCondition(new ConditionType(Either.right(Either.right((ConditionValueExpression) conditionItem))), false, false);
                }
                queries.add(query);
                if (aggItem != null) {
                    aggItem.setTimeframe(rule.getDetection().getTimeframe());
                    queries.add(convertAggregation(aggItem));
                }
            }

            this.queryFields.putAll(this.ruleQueryFields);
        } catch (SigmaError ex) {
            if (this.collectErrors) {
                this.errors.add(Pair.of(rule, ex));
            } else {
                throw ex;
            }
        }
        return queries;
    }

    public Object convertCondition(ConditionType conditionType, boolean isConditionNot, boolean applyDeMorgans) throws SigmaValueError {
        if (conditionType.isConditionOR()) {
            if (this.decideConvertConditionAsInExpression(Either.right(conditionType.getConditionOR()))) {
                return this.convertConditionAsInExpression(Either.right(conditionType.getConditionOR()), isConditionNot, applyDeMorgans );
            } else {
                return this.convertConditionOr(conditionType.getConditionOR(), isConditionNot, applyDeMorgans);
            }
        } else if (conditionType.isConditionAND()) {
            if (this.decideConvertConditionAsInExpression(Either.left(conditionType.getConditionAND()))) {
                return this.convertConditionAsInExpression(Either.left(conditionType.getConditionAND()), isConditionNot, applyDeMorgans);
            } else {
                return this.convertConditionAnd(conditionType.getConditionAND(), isConditionNot, applyDeMorgans);
            }
        } else if (conditionType.isConditionNOT()) {
            return this.convertConditionNot(conditionType.getConditionNOT(), isConditionNot, applyDeMorgans);
        } else if (conditionType.isEqualsValueExpression()) {
            // check to see if conditionNot is an ancestor of the parse tree, otherwise return as normal
            if (isConditionNot) {
                return this.convertConditionFieldEqValNot(conditionType, isConditionNot, applyDeMorgans);
            } else {
                return this.convertConditionFieldEqVal(conditionType.getEqualsValueExpression(), isConditionNot, applyDeMorgans);
            }
        } else if (conditionType.isValueExpression()) {
            return this.convertConditionVal(conditionType.getValueExpression(), applyDeMorgans);
        } else {
            throw new IllegalArgumentException("Unexpected data type in condition parse tree");
        }
    }

    public String convertConditionFieldEqValNot(ConditionType conditionType, boolean isConditionNot, boolean applyDeMorgans) throws SigmaValueError {
        String baseString = this.convertConditionFieldEqVal(conditionType.getEqualsValueExpression(), isConditionNot, applyDeMorgans).toString();
        String addExists = this.convertExistsField(conditionType.getEqualsValueExpression()).toString();
        return String.format(Locale.getDefault(), ("%s" + "%s"), baseString, addExists);
    }

    public boolean decideConvertConditionAsInExpression(Either<ConditionAND, ConditionOR> condition) {
        if ((!this.convertOrAsIn && condition.isRight()) || (!this.convertAndAsIn && condition.isLeft())) {
            return false;
        }

        ConditionItem cond = condition.isLeft()? condition.getLeft(): condition.get();

        for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: cond.getArgs()) {
            if (arg.isLeft() || !arg.getLeft().isMiddle()) {
                return false;
            }
        }

        Set<String> fields = new HashSet<>();
        for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: cond.getArgs()) {
            ConditionFieldEqualsValueExpression equalsValueExpression = arg.getLeft().getMiddle();
            fields.add(equalsValueExpression.getField());
        }

        if (fields.size() != 1) {
            return false;
        }

        for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: cond.getArgs()) {
            ConditionFieldEqualsValueExpression equalsValueExpression = arg.getLeft().getMiddle();

            if (!(equalsValueExpression.getValue() instanceof SigmaString) && !(equalsValueExpression.getValue() instanceof SigmaNumber)) {
                return false;
            }
        }
        return true;
    }

    public Map<String, Object> getQueryFields() {
        return queryFields;
    }

    public void resetQueryFields() {
        queryFields.clear();
        if (ruleQueryFields != null) {
            ruleQueryFields.clear();
        }
    }

    public abstract Object convertConditionAsInExpression(Either<ConditionAND, ConditionOR> condition, boolean isConditionNot, boolean applyDeMorgans);

    public abstract Object convertConditionAnd(ConditionAND condition, boolean isConditionNot, boolean applyDeMorgans);

    public abstract Object convertConditionOr(ConditionOR condition, boolean isConditionNot, boolean applyDeMorgans);

    public abstract Object convertConditionNot(ConditionNOT condition, boolean isConditionNot, boolean applyDeMorgans);

    public Object convertConditionFieldEqVal(ConditionFieldEqualsValueExpression condition, boolean isConditionNot, boolean applyDeMorgans) throws SigmaValueError {
        if (condition.getValue() instanceof SigmaString) {
            return this.convertConditionFieldEqValStr(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaNumber) {
            return this.convertConditionFieldEqValNum(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaBool) {
            return this.convertConditionFieldEqValBool(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaRegularExpression) {
            return this.convertConditionFieldEqValRe(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaCIDRExpression) {
            return this.convertConditionFieldEqValCidr(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaCompareExpression) {
            return this.convertConditionFieldEqValOpVal(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaNull) {
            return this.convertConditionFieldEqValNull(condition, applyDeMorgans);
        }/* TODO: below methods will be supported when Sigma Expand Modifier is supported.
        else if (condition.getValue() instanceof SigmaQueryExpression) {
            return this.convertConditionFieldEqValQueryExpr(condition);
        }*/ else if (condition.getValue() instanceof SigmaExpansion) {
            return this.convertConditionFieldEqValQueryExpansion(condition, isConditionNot, applyDeMorgans);
        } else {
            throw new IllegalArgumentException("Unexpected value type class in condition parse tree: " + condition.getValue().getClass().getName());
        }
    }

    public abstract Object convertConditionFieldEqValStr(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans) throws SigmaValueError;

    public abstract Object convertConditionFieldEqValNum(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertConditionFieldEqValBool(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertConditionFieldEqValRe(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertConditionFieldEqValCidr(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

   public abstract Object convertConditionFieldEqValOpVal(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertExistsField(ConditionFieldEqualsValueExpression condition);

        /*    public abstract Object convertConditionFieldEqValQueryExpr(ConditionFieldEqualsValueExpression condition);*/

    public Object convertConditionFieldEqValQueryExpansion(ConditionFieldEqualsValueExpression condition, boolean isConditionNot, boolean applyDeMorgans) {
        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args = new ArrayList<>();
        for (SigmaType sigmaType: ((SigmaExpansion) condition.getValue()).getValues()) {
            args.add(Either.left(AnyOneOf.middleVal(new ConditionFieldEqualsValueExpression(condition.getField(), sigmaType))));
        }

        ConditionOR conditionOR = new ConditionOR(false, args);
        return this.convertConditionOr(conditionOR, isConditionNot, applyDeMorgans);
    }

    public Object convertConditionVal(ConditionValueExpression condition, boolean applyDeMorgans) throws SigmaValueError {
        if (condition.getValue() instanceof SigmaString) {
            return this.convertConditionValStr(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaNumber) {
            return this.convertConditionValNum(condition, applyDeMorgans);
        } else if (condition.getValue() instanceof SigmaBool) {
            throw new SigmaValueError("Boolean values can't appear as standalone value without a field name.");
        } else if (condition.getValue() instanceof SigmaRegularExpression) {
            return this.convertConditionValRe(condition, applyDeMorgans);
        }/* else if (condition.getValue() instanceof SigmaCIDRExpression) {
            throw new SigmaValueError("CIDR values can't appear as standalone value without a field name.");
        } else if (condition.getValue() instanceof SigmaQueryExpression) {
            return this.convertConditionValQueryExpr(condition);
        }*/ else {
            throw new IllegalArgumentException("Unexpected value type class in condition parse tree: " + condition.getValue().getClass().getName());
        }
    }

    public abstract Object convertConditionValStr(ConditionValueExpression condition, boolean applyDeMorgans) throws SigmaValueError;

    public abstract Object convertConditionValNum(ConditionValueExpression condition, boolean applyDeMorgans);

    public abstract Object convertConditionValRe(ConditionValueExpression condition, boolean applyDeMorgans);

/*   public abstract Object convertConditionValQueryExpr(ConditionValueExpression condition);*/

    public abstract AggregationQueries convertAggregation(AggregationItem aggregation) throws SigmaError;
}
