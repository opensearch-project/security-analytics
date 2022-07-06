/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionType;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.apache.commons.lang3.NotImplementedException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Locale;

public class OSQueryBackend extends QueryBackend {

    private String tokenSeparator;

    private String orToken;

    private String andToken;

    private String notToken;

    private String escapeChar;

    private String wildcardMulti;

    private String wildcardSingle;

    private String addEscaped;

    private String eqToken;

    private String strQuote;

    private List<String> reEscape;

    private String reEscapeChar;

    private String reExpression;

    private String cidrExpression;

    private String fieldNullExpression;

    private String unboundValueStrExpression;

    private String unboundValueNumExpression;

    private String unboundReExpression;

    private String compareOpExpression;

    private static final String groupExpression = "(%s)";
    private static final Map<String, String> compareOperators = Map.of(
            SigmaCompareExpression.CompareOperators.GT, "gt",
            SigmaCompareExpression.CompareOperators.GTE, "gte",
            SigmaCompareExpression.CompareOperators.LT, "lt",
            SigmaCompareExpression.CompareOperators.LTE, "lte"
    );

    private static final List<Class<?>> precedence = Arrays.asList(ConditionNOT.class, ConditionAND.class, ConditionOR.class);

    public OSQueryBackend(boolean collectErrors, boolean enableFieldMappings) throws IOException {
        super(true, enableFieldMappings, true, collectErrors);
        this.tokenSeparator = " ";
        this.orToken = "OR";
        this.andToken = "AND";
        this.notToken = "NOT";
        this.escapeChar = "\\";
        this.wildcardMulti = "*";
        this.wildcardSingle = "*";
        this.addEscaped = "\\";
        this.eqToken = ":";
        this.strQuote = "\"";
        this.reEscape = Arrays.asList("\"");
        this.reEscapeChar = "\\";
        this.reExpression = "\"%s\" : \"%s\"";
        this.cidrExpression = "\"%s\" : \"%s\"";
        this.fieldNullExpression = "\"%s\" : null";
        this.unboundValueStrExpression = "\"_\" : \"%s\"";
        this.unboundValueNumExpression = "\"_\" : %s";
        this.unboundReExpression = "\"_\" : \"%s\"";
        this.compareOpExpression = "\"%s\" \"%s\" %s";
    }

    @Override
    public Object convertConditionAsInExpression(Either<ConditionAND, ConditionOR> condition) {
        if (condition.isLeft()) {
            return this.convertConditionAnd(condition.getLeft());
        }
        return this.convertConditionOr(condition.get());
    }

    @Override
    public Object convertConditionAnd(ConditionAND condition) {
        try {
            StringBuilder queryBuilder = new StringBuilder();
            StringBuilder joiner = new StringBuilder();
            if (this.tokenSeparator.equals(this.andToken)) {
                joiner.append(this.andToken);
            } else {
                joiner.append(this.tokenSeparator).append(this.andToken).append(this.tokenSeparator);
            }

            boolean first = true;
            for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: condition.getArgs()) {
                boolean prec;
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.leftVal(condition))), argType);

                        if (prec) {
                            converted = this.convertCondition(argType);
                        } else {
                            converted = this.convertConditionGroup(argType);
                        }
                    } else if (arg.getLeft().isMiddle()) {
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.leftVal(condition))),
                                new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        if (prec) {
                            converted = this.convertCondition(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        } else {
                            converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        }
                    } else if (arg.getLeft().isRight()) {
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.leftVal(condition))),
                                new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        if (prec) {
                            converted = this.convertCondition(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        } else {
                            converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        }
                    }

                    if (converted != null) {
                        if (!first) {
                            queryBuilder.append(joiner).append(converted);
                        } else {
                            queryBuilder.append(converted);
                            first = false;
                        }

                    }
                }
            }
            return queryBuilder.toString();
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'and' not supported by the backend");
        }
    }

    @Override
    public Object convertConditionOr(ConditionOR condition) {
        try {
            StringBuilder queryBuilder = new StringBuilder();
            StringBuilder joiner = new StringBuilder();
            if (this.tokenSeparator.equals(this.orToken)) {
                joiner.append(this.orToken);
            } else {
                joiner.append(this.tokenSeparator).append(this.orToken).append(this.tokenSeparator);
            }

            boolean first = true;
            for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg: condition.getArgs()) {
                boolean prec;
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.middleVal(condition))), argType);

                        if (prec) {
                            converted = this.convertCondition(argType);
                        } else {
                            converted = this.convertConditionGroup(argType);
                        }
                    } else if (arg.getLeft().isMiddle()) {
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.middleVal(condition))),
                                new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        if (prec) {
                            converted = this.convertCondition(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        } else {
                            converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                        }
                    } else if (arg.getLeft().isRight()) {
                        prec = comparePrecedence(new ConditionType(Either.left(AnyOneOf.middleVal(condition))),
                                new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        if (prec) {
                            converted = this.convertCondition(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        } else {
                            converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
                        }
                    }

                    if (converted != null) {
                        if (!first) {
                            queryBuilder.append(joiner).append(converted);
                        } else {
                            queryBuilder.append(converted);
                            first = false;
                        }

                    }
                }
            }
            return queryBuilder.toString();
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'and' not supported by the backend");
        }
    }

    @Override
    public Object convertConditionNot(ConditionNOT condition) {
        Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg = condition.getArgs().get(0);
        try {
            if (arg.isLeft()) {
                if (arg.getLeft().isLeft()) {
                    ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class) ? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))) :
                            (arg.getLeft().getLeft().getClass().equals(ConditionOR.class) ? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))) :
                                    new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                    return this.notToken + this.tokenSeparator + this.convertConditionGroup(argType);
                } else if (arg.getLeft().isMiddle()) {
                    ConditionType argType = new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle())));
                    return this.notToken + this.tokenSeparator + this.convertCondition(argType).toString();
                } else {
                    ConditionType argType = new ConditionType(Either.right(Either.right(arg.getLeft().get())));
                    return this.notToken + this.tokenSeparator + this.convertCondition(argType).toString();
                }
            }
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'not' not supported by the backend");
        }
        return null;
    }

    @Override
    public Object convertConditionFieldEqValStr(ConditionFieldEqualsValueExpression condition) throws SigmaValueError {
        String expr = this.strQuote + "%s" + this.strQuote + " " + this.eqToken + " " + this.strQuote + "%s" + this.strQuote;
        SigmaString value = (SigmaString) condition.getValue();
        return String.format(Locale.getDefault(), expr, this.getMappedField(condition.getField()), this.convertValueStr(value));
    }

    @Override
    public Object convertConditionFieldEqValNum(ConditionFieldEqualsValueExpression condition) {
        return this.strQuote + this.getMappedField(condition.getField()) + this.strQuote + " " + this.eqToken + " " + condition.getValue();
    }

    @Override
    public Object convertConditionFieldEqValBool(ConditionFieldEqualsValueExpression condition) {
        return this.strQuote + this.getMappedField(condition.getField()) + this.strQuote + " " + this.eqToken + " " + ((SigmaBool) condition.getValue()).isaBoolean();
    }

    public Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.fieldNullExpression, this.getMappedField(condition.getField()));
    }

    @Override
    public Object convertConditionFieldEqValRe(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.reExpression, this.getMappedField(condition.getField()), convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValCidr(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.cidrExpression, this.getMappedField(condition.getField()), convertValueCidr((SigmaCIDRExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValOpVal(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.compareOpExpression, this.getMappedField(condition.getField()),
                compareOperators.get(((SigmaCompareExpression) condition.getValue()).getOp()), ((SigmaCompareExpression) condition.getValue()).getNumber().toString());
    }

/*    @Override
    public Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition) {
        return null;
    }

    @Override
    public Object convertConditionFieldEqValQueryExpr(ConditionFieldEqualsValueExpression condition) {
        return null;
    }*/

    @Override
    public Object convertConditionValStr(ConditionValueExpression condition) throws SigmaValueError {
        return String.format(Locale.getDefault(), this.unboundValueStrExpression, this.convertValueStr((SigmaString) condition.getValue()));
    }

    @Override
    public Object convertConditionValNum(ConditionValueExpression condition) {
        return String.format(Locale.getDefault(), this.unboundValueNumExpression, condition.getValue().toString());
    }

    @Override
    public Object convertConditionValRe(ConditionValueExpression condition) {
        return String.format(Locale.getDefault(), this.unboundReExpression, convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

/*    @Override
    public Object convertConditionValQueryExpr(ConditionValueExpression condition) {
        return null;
    }*/

    private boolean comparePrecedence(ConditionType outer, ConditionType inner) {
        Class<?> outerClass = outer.getClazz();

        Class<?> innerClass = inner.getClazz();
        if ((inner.isEqualsValueExpression() && inner.getEqualsValueExpression().getValue() instanceof SigmaExpansion) ||
                (inner.isValueExpression() && inner.getValueExpression().getValue() instanceof SigmaExpansion)) {
            innerClass = ConditionOR.class;
        }

        int idxInner = precedence.indexOf(innerClass);
        return idxInner <= precedence.indexOf(outerClass);
    }

    private Object convertConditionGroup(ConditionType condition) throws SigmaValueError {
        return String.format(Locale.getDefault(), groupExpression, this.convertCondition(condition));
    }

    private Object convertValueStr(SigmaString s) throws SigmaValueError {
        return s.convert(escapeChar, wildcardMulti, wildcardSingle, addEscaped, "");
    }

    private Object convertValueRe(SigmaRegularExpression re) {
        return re.escape(this.reEscape, this.reEscapeChar);
    }

    private Object convertValueCidr(SigmaCIDRExpression ip) {
        return ip.convert();
    }

    private String getMappedField(String field) {
        if (this.enableFieldMappings && this.fieldMappings.containsKey(field)) {
            return this.fieldMappings.get(field);
        }
        return field;
    }
}