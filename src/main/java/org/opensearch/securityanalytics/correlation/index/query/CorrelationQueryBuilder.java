/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.query;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.Query;
import org.opensearch.common.ParsingException;
import org.opensearch.common.Strings;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.mapper.MappedFieldType;
import org.opensearch.index.mapper.NumberFieldMapper;
import org.opensearch.index.query.AbstractQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.securityanalytics.correlation.index.mapper.CorrelationVectorFieldMapper;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public class CorrelationQueryBuilder extends AbstractQueryBuilder<CorrelationQueryBuilder> {

    private static final Logger log = LogManager.getLogger(CorrelationQueryBuilder.class);
    public static final ParseField VECTOR_FIELD = new ParseField("vector");
    public static final ParseField K_FIELD = new ParseField("k");
    public static final ParseField FILTER_FIELD = new ParseField("filter");
    public static int K_MAX = 10000;

    public static final String NAME = "correlation";

    private final String fieldName;
    private final float[] vector;
    private int k = 0;
    private QueryBuilder filter;

    public CorrelationQueryBuilder(String fieldName, float[] vector, int k) {
        this(fieldName, vector, k, null);
    }

    public CorrelationQueryBuilder(String fieldName, float[] vector, int k, QueryBuilder filter) {
        if (Strings.isNullOrEmpty(fieldName)) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "[%s] requires fieldName", NAME));
        }
        if (vector == null) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "[%s] requires query vector", NAME));
        }
        if (vector.length == 0) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "[%s] query vector is empty", NAME));
        }
        if (k <= 0) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "[%s] requires k > 0", NAME));
        }
        if (k > K_MAX) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "[%s] requires k <= ", K_MAX));
        }

        this.fieldName = fieldName;
        this.vector = vector;
        this.k = k;
        this.filter = filter;
    }

    public CorrelationQueryBuilder(StreamInput sin) throws IOException {
        super(sin);
        try {
            this.fieldName = sin.readString();
            this.vector = sin.readFloatArray();
            this.k = sin.readInt();
            this.filter = sin.readOptionalNamedWriteable(QueryBuilder.class);
        } catch (IOException ex) {
            throw new RuntimeException("Unable to create CorrelationQueryBuilder", ex);
        }
    }

    private static float[] objectsToFloats(List<Object> objs) {
        float[] vector = new float[objs.size()];
        for (int i = 0; i < objs.size(); ++i) {
            vector[i] = ((Number) objs.get(i)).floatValue();
        }
        return vector;
    }

    public static CorrelationQueryBuilder fromXContent(XContentParser parser) throws IOException {
        String fieldName = null;
        List<Object> vector = null;
        float boost = AbstractQueryBuilder.DEFAULT_BOOST;

        int k = 0;
        QueryBuilder filter = null;
        String queryName = null;
        String currentFieldName = null;
        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token == XContentParser.Token.START_OBJECT) {
                throwParsingExceptionOnMultipleFields(NAME, parser.getTokenLocation(), fieldName, currentFieldName);
                fieldName = currentFieldName;
                while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                    if (token == XContentParser.Token.FIELD_NAME) {
                        currentFieldName = parser.currentName();
                    } else if (token.isValue() || token == XContentParser.Token.START_ARRAY) {
                        if (VECTOR_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                            vector = parser.list();
                        } else if (AbstractQueryBuilder.BOOST_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                            boost = parser.floatValue();
                        } else if (K_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                            k = (Integer) NumberFieldMapper.NumberType.INTEGER.parse(parser.objectBytes(), false);
                        } else if (AbstractQueryBuilder.NAME_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                            queryName = parser.text();
                        } else {
                            throw new ParsingException(
                                    parser.getTokenLocation(),
                                    "[" + NAME + "] query does not support [" + currentFieldName + "]"
                            );
                        }
                    } else if (token == XContentParser.Token.START_OBJECT) {
                        String tokenName = parser.currentName();
                        if (FILTER_FIELD.getPreferredName().equals(tokenName)) {
                            filter = parseInnerQueryBuilder(parser);
                        }  else {
                            throw new ParsingException(parser.getTokenLocation(), "[" + NAME + "] unknown token [" + token + "]");
                        }
                    } else {
                        throw new ParsingException(
                                parser.getTokenLocation(),
                                "[" + NAME + "] unknown token [" + token + "] after [" + currentFieldName + "]"
                        );
                    }
                }
            } else {
                throwParsingExceptionOnMultipleFields(NAME, parser.getTokenLocation(), fieldName, parser.currentName());
                fieldName = parser.currentName();
                vector = parser.list();
            }
        }

        assert vector != null;
        CorrelationQueryBuilder correlationQueryBuilder = new CorrelationQueryBuilder(fieldName, objectsToFloats(vector), k, filter);
        correlationQueryBuilder.queryName(queryName);
        correlationQueryBuilder.boost(boost);
        return correlationQueryBuilder;
    }

    public String fieldName() {
        return fieldName;
    }

    public Object vector() {
        return vector;
    }

    public int getK() {
        return k;
    }

    public QueryBuilder getFilter() {
        return filter;
    }

    @Override
    protected void doWriteTo(StreamOutput out) throws IOException {
        out.writeString(fieldName);
        out.writeFloatArray(vector);
        out.writeInt(k);
        out.writeOptionalNamedWriteable(filter);
    }

    @Override
    public void doXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(NAME);
        builder.startObject(fieldName);

        builder.field(VECTOR_FIELD.getPreferredName(), vector);
        builder.field(K_FIELD.getPreferredName(), k);
        if (filter != null) {
            builder.field(FILTER_FIELD.getPreferredName(), filter);
        }
        printBoostAndQueryName(builder);
        builder.endObject();
        builder.endObject();
    }

    @Override
    protected Query doToQuery(QueryShardContext context) throws IOException {
        MappedFieldType mappedFieldType = context.fieldMapper(fieldName);

        if (!(mappedFieldType instanceof CorrelationVectorFieldMapper.CorrelationVectorFieldType)) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "Field '%s' is not knn_vector type.", this.fieldName));
        }

        CorrelationVectorFieldMapper.CorrelationVectorFieldType correlationVectorFieldType = (CorrelationVectorFieldMapper.CorrelationVectorFieldType) mappedFieldType;
        int fieldDimension = correlationVectorFieldType.getDimension();

        if (fieldDimension != vector.length) {
            throw new IllegalArgumentException(
                    String.format(Locale.getDefault(), "Query vector has invalid dimension: %d. Dimension should be: %d", vector.length, fieldDimension)
            );
        }

        String indexName = context.index().getName();
        CorrelationQueryFactory.CreateQueryRequest createQueryRequest = new CorrelationQueryFactory.CreateQueryRequest(
                indexName,
                this.fieldName,
                this.vector,
                this.k,
                this.filter,
                context
        );
        return CorrelationQueryFactory.create(createQueryRequest);
    }

    @Override
    protected boolean doEquals(CorrelationQueryBuilder other) {
        return Objects.equals(fieldName, other.fieldName) && Arrays.equals(vector, other.vector) && Objects.equals(k, other.k);
    }

    @Override
    protected int doHashCode() {
        return Objects.hash(fieldName, vector, k);
    }

    @Override
    public String getWriteableName() {
        return NAME;
    }
}