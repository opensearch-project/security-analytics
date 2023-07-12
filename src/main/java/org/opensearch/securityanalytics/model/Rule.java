/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.Detector.LAST_UPDATE_TIME_FIELD;
import static org.opensearch.securityanalytics.model.Detector.NO_ID;
import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;


public class Rule implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(Rule.class);

    public static final String CATEGORY = "category";
    public static final String TITLE = "title";
    public static final String LOG_SOURCE = "log_source";
    public static final String DESCRIPTION = "description";

    public static final String TAGS = "tags";
    public static final String REFERENCES = "references";

    public static final String LEVEL = "level";
    public static final String FALSE_POSITIVES = "false_positives";

    public static final String AUTHOR = "author";
    public static final String STATUS = "status";

    private static final String QUERIES = "queries";
    public static final String QUERY_FIELD_NAMES = "query_field_names";

    public static final String RULE = "rule";

    public static final String PRE_PACKAGED_RULES_INDEX = ".opensearch-sap-pre-packaged-rules-config";
    public static final String CUSTOM_RULES_INDEX = ".opensearch-sap-custom-rules-config";
    public static final String AGGREGATION_QUERIES = "aggregationQueries";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            Rule.class,
            new ParseField(CATEGORY),
            xcp -> parse(xcp, null, null)
    );

    private String id;

    private Long version;

    private String title;

    private String category;

    private String logSource;

    private String description;

    private List<Value> references;

    private List<Value> tags;

    private String level;

    private List<Value> falsePositives;

    private String author;

    private String status;

    private Instant date;

    private List<Value> queries;

    private List<Value> queryFieldNames;

    private String rule;

    private List<Value> aggregationQueries;

    public Rule(String id, Long version, String title, String category, String logSource,
                String description, List<Value> references, List<Value> tags, String level,
                List<Value> falsePositives, String author, String status, Instant date,
                List<Value> queries, List<Value> queryFieldNames, String rule, List<Value> aggregationQueries) {
        this.id = id != null? id: NO_ID;
        this.version = version != null? version: NO_VERSION;

        this.title = title;
        this.category = category;
        this.logSource = logSource;
        this.description = description;

        this.references = references;
        this.tags = tags;

        this.level = level;
        this.falsePositives = falsePositives;

        this.author = author;
        this.status = status;

        this.date = date;

        this.queries = queries;
        this.queryFieldNames = queryFieldNames;
        this.rule = rule;
        this.aggregationQueries = aggregationQueries;
    }

    public Rule(String id, Long version, SigmaRule rule, String category,
                List<Object> queries, List<String> queryFieldNames, String original) {
        this(
                id,
                version,
                rule.getTitle(),
                category,
                rule.getLogSource().getCategory() != null? rule.getLogSource().getCategory():
                        (rule.getLogSource().getProduct() != null? rule.getLogSource().getProduct(): rule.getLogSource().getService()),
                rule.getDescription(),
                rule.getReferences().stream().map(Value::new).collect(Collectors.toList()),
                rule.getTags().stream().map(ruleTag -> new Value(String.format(Locale.getDefault(), "%s.%s", ruleTag.getNamespace(), ruleTag.getName())))
                        .collect(Collectors.toList()),
                rule.getLevel().toString(),
                rule.getFalsePositives().stream().map(Value::new).collect(Collectors.toList()),
                rule.getAuthor(),
                rule.getStatus().toString(),
                Instant.ofEpochMilli(rule.getDate().getTime()),
                queries.stream().filter(query -> !(query instanceof AggregationQueries)).map(query -> new Value(query.toString())).collect(Collectors.toList()),
                queryFieldNames.stream().map(Value::new).collect(Collectors.toList()),
                original,
                // If one of the queries is AggregationQuery -> the whole rule can be considered as Agg
                queries.stream().filter(query -> query instanceof AggregationQueries).map(it -> new Value(it.toString())).collect(Collectors.toList()));
    }

    public Rule(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readList(Value::readFrom),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readString(),
                sin.readInstant(),
                sin.readList(Value::readFrom),
                sin.readList(Value::readFrom),
                sin.readString(),
                sin.readList(Value::readFrom)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);

        out.writeString(title);
        out.writeString(category);
        out.writeString(logSource);
        out.writeString(description);

        out.writeCollection(references);
        out.writeCollection(tags);

        out.writeString(level);
        out.writeCollection(falsePositives);

        out.writeString(author);
        out.writeString(status);
        out.writeInstant(date);

        out.writeCollection(queries);
        out.writeCollection(queryFieldNames);

        out.writeString(rule);
        out.writeCollection(aggregationQueries);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params);
    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        if (params.paramAsBoolean("with_type", false)) {
            builder.startObject("rule");
        }

        builder.field(CATEGORY, category)
                .field(TITLE, title)
                .field(LOG_SOURCE, logSource)
                .field(DESCRIPTION, description);

        Value[] refArray = new Value[]{};
        refArray = references.toArray(refArray);
        builder.field(REFERENCES, refArray);

        Value[] tagArray = new Value[]{};
        tagArray = tags.toArray(tagArray);
        builder.field(TAGS, tagArray);

        builder.field(LEVEL, level);

        Value[] falsePosArray = new Value[]{};
        falsePosArray = falsePositives.toArray(falsePosArray);
        builder.field(FALSE_POSITIVES, falsePosArray);

        builder.field(AUTHOR, author);
        builder.field(STATUS, status);
        builder.timeField(LAST_UPDATE_TIME_FIELD, date);

        Value[] queryArray = new Value[]{};
        queryArray = queries.toArray(queryArray);
        builder.field(QUERIES, queryArray);
        Value[] queryFieldNamesArray = new Value[]{};
        queryFieldNamesArray = queryFieldNames.toArray(queryFieldNamesArray);
        builder.field(QUERY_FIELD_NAMES, queryFieldNamesArray);

        Value[] aggregationsArray = new Value[]{};
        aggregationsArray = aggregationQueries.toArray(aggregationsArray);
        builder.field(AGGREGATION_QUERIES, aggregationsArray);

        builder.field(RULE, rule);
        if (params.paramAsBoolean("with_type", false)) {
            builder.endObject();
        }
        return builder.endObject();
    }

    public static Rule docParse(XContentParser xcp, String id, Long version) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        Rule rule = parse(xcp, id, version);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        rule.setId(id);
        rule.setVersion(version);
        return rule;
    }

    public static Rule parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String title = null;
        String category = null;
        String logSource = null;
        String description = null;

        List<Value> references = new ArrayList<>();
        List<Value> tags = new ArrayList<>();

        String level = null;
        List<Value> falsePositives = new ArrayList<>();

        String author = null;
        String status = null;
        Instant date = null;

        List<Value> queries = new ArrayList<>();
        List<Value> queryFields = new ArrayList<>();
        String original = null;
        List<Value> aggregationQueries = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case TITLE:
                    title = xcp.text();
                    break;
                case CATEGORY:
                    category = xcp.text();
                    break;
                case LOG_SOURCE:
                    logSource = xcp.text();
                    break;
                case DESCRIPTION:
                    description = xcp.text();
                    break;
                case REFERENCES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        references.add(Value.parse(xcp));
                    }
                    break;
                case TAGS:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        tags.add(Value.parse(xcp));
                    }
                    break;
                case LEVEL:
                    level = xcp.text();
                    break;
                case FALSE_POSITIVES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        falsePositives.add(Value.parse(xcp));
                    }
                    break;
                case AUTHOR:
                    author = xcp.text();
                    break;
                case STATUS:
                    status = xcp.text();
                    break;
                case LAST_UPDATE_TIME_FIELD:
                    date = Instant.parse(xcp.text());
                    break;
                case QUERIES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        queries.add(Value.parse(xcp));
                    }
                    break;
                case QUERY_FIELD_NAMES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        queryFields.add(Value.parse(xcp));
                    }
                    break;
                case RULE:
                    original = xcp.text();
                    break;
                case AGGREGATION_QUERIES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        aggregationQueries.add(Value.parse(xcp));
                    }
                default:
                    xcp.skipChildren();
            }
        }

        return new Rule(
                id,
                version,
                Objects.requireNonNull(title, "Rule Title is null"),
                Objects.requireNonNull(category, "Rule Category is null"),
                Objects.requireNonNull(logSource, "Rule LogSource is null"),
                description,
                references,
                tags,
                level,
                falsePositives,
                author,
                status,
                date,
                queries,
                queryFields,
                Objects.requireNonNull(original, "Rule String is null"),
                aggregationQueries
        );
    }

    public static Rule readFrom(StreamInput sin) throws IOException {
        return new Rule(sin);
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public String getCategory() {
        return category;
    }

    public String getTitle() {
        return title;
    }

    public String getLogSource() {
        return logSource;
    }

    public String getDescription() {
        return description;
    }

    public List<Value> getTags() {
        return tags;
    }

    public List<Value> getReferences() {
        return references;
    }

    public String getLevel() {
        return level;
    }

    public List<Value> getFalsePositives() {
        return falsePositives;
    }

    public String getAuthor() {
        return author;
    }

    public String getStatus() {
        return status;
    }

    public Instant getDate() {
        return date;
    }

    public String getRule() {
        return rule;
    }

    public List<Value> getQueries() {
        return queries;
    }

    public List<Value> getQueryFieldNames() {
        return queryFieldNames;
    }

    public List<Value> getAggregationQueries() { return aggregationQueries; }

    public boolean isAggregationRule() {
        return aggregationQueries != null && !aggregationQueries.isEmpty();
    }

    public List<AggregationItem> getAggregationItemsFromRule () throws SigmaError {
        SigmaRule sigmaRule = SigmaRule.fromYaml(rule, true);
        List<AggregationItem> aggregationItems = new ArrayList<>();
        for (SigmaCondition condition: sigmaRule.getDetection().getParsedCondition()) {
            Pair<ConditionItem, AggregationItem> parsedItems = condition.parsed();
            AggregationItem aggItem = parsedItems.getRight();
            aggregationItems.add(aggItem);
        }
        return aggregationItems;
    }
}