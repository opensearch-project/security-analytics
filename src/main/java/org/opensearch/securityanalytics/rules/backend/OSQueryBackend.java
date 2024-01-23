/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.backend;

import org.opensearch.OpenSearchParseException;
import org.opensearch.common.UUIDs;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder;
import org.opensearch.script.Script;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
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
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.apache.commons.lang3.NotImplementedException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class OSQueryBackend extends QueryBackend {

    private String tokenSeparator;

    private String orToken;

    private String andToken;

    private String notToken;

    private String escapeChar;

    private String wildcardMulti;

    private String wildcardSingle;

    private String addEscaped;

    private String addReserved;

    private String eqToken;

    private String strQuote;

    private String reQuote;

    private List<String> reEscape;

    private String reEscapeChar;

    private String reExpression;

    private String cidrExpression;

    private String fieldNullExpression;

    private String unboundValueStrExpression;

    private String unboundValueNumExpression;

    private String unboundWildcardExpression;

    private String unboundReExpression;

    private String compareOpExpression;

    private int valExpCount;

    private String aggQuery;

    private String aggCountQuery;

    private String bucketTriggerQuery;

    private String bucketTriggerScript;

    private static final String groupExpression = "(%s)";
    private static final Map<String, String> compareOperators = Map.of(
            SigmaCompareExpression.CompareOperators.GT, "gt",
            SigmaCompareExpression.CompareOperators.GTE, "gte",
            SigmaCompareExpression.CompareOperators.LT, "lt",
            SigmaCompareExpression.CompareOperators.LTE, "lte"
    );

    private static final List<Class<?>> precedence = Arrays.asList(ConditionNOT.class, ConditionAND.class, ConditionOR.class);

    public OSQueryBackend(Map<String, String> fieldMappings, boolean collectErrors, boolean enableFieldMappings) throws IOException {
        super(fieldMappings, true, enableFieldMappings, true, collectErrors);
        this.tokenSeparator = " ";
        this.orToken = "OR";
        this.andToken = "AND";
        this.notToken = "NOT";
        this.escapeChar = "\\";
        this.wildcardMulti = "*";
        this.wildcardSingle = "?";
        this.addEscaped = "/:\\+-=><!(){}[]^\"~*?";
        this.addReserved = "&& ||";
        this.eqToken = ":";
        this.strQuote = "\"";
        this.reQuote = "";
        this.reEscape = Arrays.asList("\"");
        this.reEscapeChar = "\\";
        this.reExpression = "%s: /%s/";
        this.cidrExpression = "%s: \"%s\"";
        this.fieldNullExpression = "%s: (NOT [* TO *])";
        this.unboundValueStrExpression = "\"%s\"";
        this.unboundValueNumExpression = "\"%s\"";
        this.unboundWildcardExpression = "%s";
        this.unboundReExpression = "/%s/";
        this.compareOpExpression = "\"%s\" \"%s\" %s";
        this.valExpCount = 0;
        this.aggQuery = "{\"%s\":{\"terms\":{\"field\":\"%s\"},\"aggs\":{\"%s\":{\"%s\":{\"field\":\"%s\"}}}}}";
        this.aggCountQuery = "{\"%s\":{\"terms\":{\"field\":\"%s\"}}}";
        this.bucketTriggerQuery = "{\"buckets_path\":{\"%s\":\"%s\"},\"parent_bucket_path\":\"%s\",\"script\":{\"source\":\"params.%s %s %s\",\"lang\":\"painless\"}}";
        this.bucketTriggerScript = "params.%s %s %s";
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
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        converted = this.convertConditionGroup(argType);
                    } else if (arg.getLeft().isMiddle()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                    } else if (arg.getLeft().isRight()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
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
                Object converted = null;
                if (arg.isLeft()) {
                    if (arg.getLeft().isLeft()) {
                        ConditionType argType = arg.getLeft().getLeft().getClass().equals(ConditionAND.class)? new ConditionType(Either.left(AnyOneOf.leftVal((ConditionAND) arg.getLeft().getLeft()))):
                                (arg.getLeft().getLeft().getClass().equals(ConditionOR.class)? new ConditionType(Either.left(AnyOneOf.middleVal((ConditionOR) arg.getLeft().getLeft()))):
                                        new ConditionType(Either.left(AnyOneOf.rightVal((ConditionNOT) arg.getLeft().getLeft()))));
                        converted = this.convertConditionGroup(argType);
                    } else if (arg.getLeft().isMiddle()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle()))));
                    } else if (arg.getLeft().isRight()) {
                        converted = this.convertConditionGroup(new ConditionType(Either.right(Either.right(arg.getLeft().get()))));
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
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertConditionGroup(argType));
                } else if (arg.getLeft().isMiddle()) {
                    ConditionType argType = new ConditionType(Either.right(Either.left(arg.getLeft().getMiddle())));
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertCondition(argType).toString());
                } else {
                    ConditionType argType = new ConditionType(Either.right(Either.right(arg.getLeft().get())));
                    return String.format(Locale.getDefault(), groupExpression, this.notToken + this.tokenSeparator + this.convertCondition(argType).toString());
                }
            }
        } catch (Exception ex) {
            throw new NotImplementedException("Operator 'not' not supported by the backend");
        }
        return null;
    }

    @Override
    public Object convertConditionFieldEqValStr(ConditionFieldEqualsValueExpression condition) throws SigmaValueError {
        SigmaString value = (SigmaString) condition.getValue();
        boolean containsWildcard = value.containsWildcard();
        String expr = "%s" + this.eqToken + " " + (containsWildcard? this.reQuote: this.strQuote) + "%s" + (containsWildcard? this.reQuote: this.strQuote);

        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), expr, field, this.convertValueStr(value));
    }

    @Override
    public Object convertConditionFieldEqValNum(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());

        SigmaNumber number = (SigmaNumber) condition.getValue();
        ruleQueryFields.put(field, number.getNumOpt().isLeft()? Collections.singletonMap("type", "integer"): Collections.singletonMap("type", "float"));

        return field + this.eqToken + " " + condition.getValue();
    }

    @Override
    public Object convertConditionFieldEqValBool(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Collections.singletonMap("type", "boolean"));

        return field + this.eqToken + " " + ((SigmaBool) condition.getValue()).isaBoolean();
    }

    public Object convertConditionFieldEqValNull(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.fieldNullExpression, field);
    }

    @Override
    public Object convertConditionFieldEqValRe(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.reExpression, field, convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValCidr(ConditionFieldEqualsValueExpression condition) {
        String field = getFinalField(condition.getField());
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        return String.format(Locale.getDefault(), this.cidrExpression, field, convertValueCidr((SigmaCIDRExpression) condition.getValue()));
    }

    @Override
    public Object convertConditionFieldEqValOpVal(ConditionFieldEqualsValueExpression condition) {
        return String.format(Locale.getDefault(), this.compareOpExpression, this.getMappedField(condition.getField()),
                compareOperators.get(((SigmaCompareExpression) condition.getValue()).getOp()), ((SigmaCompareExpression) condition.getValue()).getNumber().toString());
    }

// TODO: below methods will be supported when Sigma Expand Modifier is supported.
//
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
        String field = getFinalValueField();
        ruleQueryFields.put(field, Map.of("type", "text", "analyzer", "rule_analyzer"));
        SigmaString value = (SigmaString) condition.getValue();
        boolean containsWildcard = value.containsWildcard();
        return String.format(Locale.getDefault(), (containsWildcard? this.unboundWildcardExpression: this.unboundValueStrExpression),
                this.convertValueStr((SigmaString) condition.getValue()));
    }

    @Override
    public Object convertConditionValNum(ConditionValueExpression condition) {
        return String.format(Locale.getDefault(), this.unboundValueNumExpression, condition.getValue().toString());
    }

    @Override
    public Object convertConditionValRe(ConditionValueExpression condition) {
        return String.format(Locale.getDefault(), this.unboundReExpression, convertValueRe((SigmaRegularExpression) condition.getValue()));
    }

// TODO: below methods will be supported when Sigma Expand Modifier is supported.
//
/*    @Override
    public Object convertConditionValQueryExpr(ConditionValueExpression condition) {
        return null;
    }*/

    @Override
    public AggregationQueries convertAggregation(AggregationItem aggregation) {
        String fmtAggQuery;
        String fmtBucketTriggerQuery;
        TermsAggregationBuilder aggBuilder = new TermsAggregationBuilder("result_agg");
        BucketSelectorExtAggregationBuilder condition;
        String bucketTriggerSelectorId = UUIDs.base64UUID();

        if (aggregation.getAggFunction().equals("count") && aggregation.getAggField().equals("*")) {
            String fieldName;
            if (aggregation.getGroupByField() == null) {
                fieldName = "_index";
                fmtAggQuery = String.format(Locale.getDefault(), aggCountQuery, "result_agg", "_index");
            } else {
                String mappedGroupByField = getMappedField(aggregation.getGroupByField());
                fieldName = mappedGroupByField;
                fmtAggQuery = String.format(Locale.getDefault(), aggCountQuery, "result_agg", mappedGroupByField);
            }
            aggBuilder.field(fieldName);
            fmtBucketTriggerQuery = String.format(Locale.getDefault(), bucketTriggerQuery, "_cnt", "_count", "result_agg", "_cnt", aggregation.getCompOperator(), aggregation.getThreshold());

            Script script = new Script(String.format(Locale.getDefault(), bucketTriggerScript, "_cnt", aggregation.getCompOperator(), aggregation.getThreshold()));
            condition = new BucketSelectorExtAggregationBuilder(bucketTriggerSelectorId, Collections.singletonMap("_cnt", "_count"), script, "result_agg", null);
        } else {
            /**
             * removing dots to eliminate dots in aggregation names
             */
            String mappedAggField = getFinalField(aggregation.getAggField());
            String mappedAggFieldUpdated = mappedAggField.replace(".", "_");
            String mappedGroupByField = getMappedField(aggregation.getGroupByField());
            fmtAggQuery = String.format(Locale.getDefault(), aggQuery, "result_agg", mappedGroupByField, mappedAggFieldUpdated, aggregation.getAggFunction().equals("count")? "value_count": aggregation.getAggFunction(), mappedAggField);
            fmtBucketTriggerQuery = String.format(Locale.getDefault(), bucketTriggerQuery, mappedAggFieldUpdated, mappedAggField, "result_agg", mappedAggFieldUpdated, aggregation.getCompOperator(), aggregation.getThreshold());

            // Add subaggregation
            AggregationBuilder subAgg = AggregationBuilders.getAggregationBuilderByFunction(aggregation.getAggFunction(), mappedAggField);
            if (subAgg != null) {
                aggBuilder.field(mappedGroupByField).subAggregation(subAgg);
            }

            Script script = new Script(String.format(Locale.getDefault(), bucketTriggerScript, mappedAggFieldUpdated, aggregation.getCompOperator(), aggregation.getThreshold()));
            condition = new BucketSelectorExtAggregationBuilder(bucketTriggerSelectorId, Collections.singletonMap(mappedAggFieldUpdated, mappedAggFieldUpdated), script, "result_agg", null);
        }

        AggregationQueries aggregationQueries = new AggregationQueries();
        aggregationQueries.setAggQuery(fmtAggQuery);
        aggregationQueries.setBucketTriggerQuery(fmtBucketTriggerQuery);
        aggregationQueries.setAggBuilder(aggBuilder);
        aggregationQueries.setCondition(condition);

        return aggregationQueries;
    }

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
        return s.convert(escapeChar, wildcardMulti, wildcardSingle, addEscaped, addReserved, "");
    }

    private Object convertValueRe(SigmaRegularExpression re) {
        return re.escape(this.reEscape, this.reEscapeChar);
    }

    private Object convertValueCidr(SigmaCIDRExpression ip) {
        return ip.convert();
    }

    private String getMappedField(String field) {
        if (this.enableFieldMappings && this.fieldMappings.containsKey(field) && this.fieldMappings.get(field) != null) {
            return this.fieldMappings.get(field);
        }
        return field;
    }

    private String getFinalField(String field) {
        return this.getMappedField(field);
    }

    private String getFinalValueField() {
        String field = "_" + valExpCount;
        valExpCount++;
        return field;
    }

    public static class AggregationQueries implements Writeable, ToXContentObject {
        private static final String AGG_QUERY = "aggQuery";
        private static final String BUCKET_TRIGGER_QUERY = "bucketTriggerQuery";

        public AggregationQueries() {
        }

        public AggregationQueries(StreamInput in) throws IOException {
            this.aggQuery = in.readString();
            this.bucketTriggerQuery = in.readString();
        }

        public static AggregationQueries docParse(XContentParser xcp) throws IOException{
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
            return AggregationQueries.parse(xcp);
        }

        public static AggregationQueries parse(XContentParser xcp) throws IOException {
            String aggQuery = null;
            String bucketTriggerQuery = null;

            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();

                switch (fieldName) {
                    case AGG_QUERY:
                        aggQuery = xcp.text();
                        break;
                    case BUCKET_TRIGGER_QUERY:
                        bucketTriggerQuery = xcp.text();
                        break;
                    default:
                        xcp.skipChildren();
                }
            }
            AggregationQueries aggregationQueries = new AggregationQueries();
            aggregationQueries.setAggQuery(aggQuery);
            aggregationQueries.setBucketTriggerQuery(bucketTriggerQuery);

            return aggregationQueries;
        }

        private String aggQuery;

        private AggregationBuilder aggBuilder;

        private String bucketTriggerQuery;

        private BucketSelectorExtAggregationBuilder condition;

        public String getAggQuery() {
            return aggQuery;
        }

        public void setAggQuery(String aggQuery) {
            this.aggQuery = aggQuery;
        }

        public AggregationBuilder getAggBuilder() {
            return aggBuilder;
        }

        public void setAggBuilder(AggregationBuilder aggBuilder) {
            this.aggBuilder = aggBuilder;
        }

        public String getBucketTriggerQuery() {
            return bucketTriggerQuery;
        }

        public void setBucketTriggerQuery(String bucketTriggerQuery) {
            this.bucketTriggerQuery = bucketTriggerQuery;
        }

        public BucketSelectorExtAggregationBuilder getCondition() {
            return condition;
        }

        public void setCondition(BucketSelectorExtAggregationBuilder condition) {
            this.condition = condition;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return createXContentBuilder(builder);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(aggQuery);
            out.writeString(bucketTriggerQuery);
        }

        private XContentBuilder createXContentBuilder(XContentBuilder builder) throws IOException {
            return builder.startObject().field(AGG_QUERY, aggQuery).field(BUCKET_TRIGGER_QUERY, bucketTriggerQuery).endObject();
        }

        public String toString() {
            try {
                return BytesReference.bytes(this.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)).utf8ToString();
            } catch (IOException ex) {
                throw new OpenSearchParseException("failed to convert source to a json string", new Object[0]);
            }
        }
    }
}
