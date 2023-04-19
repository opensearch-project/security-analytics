/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index;

import org.apache.lucene.index.VectorSimilarityFunction;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentFragment;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.mapper.MapperParsingException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class CorrelationParamsContext implements ToXContentFragment, Writeable {

    public static final String VECTOR_SIMILARITY_FUNCTION = "similarityFunction";
    public static final String PARAMETERS = "parameters";

    private final VectorSimilarityFunction similarityFunction;
    private final Map<String, Object> parameters;

    public CorrelationParamsContext(VectorSimilarityFunction similarityFunction, Map<String, Object> parameters) {
        this.similarityFunction = similarityFunction;
        this.parameters = parameters;
    }

    public CorrelationParamsContext(StreamInput sin) throws IOException {
        this.similarityFunction = VectorSimilarityFunction.valueOf(sin.readString());
        if (sin.available() > 0) {
            this.parameters = sin.readMap();
        } else {
            this.parameters = null;
        }
    }

    public static CorrelationParamsContext parse(Object in) {
        if (!(in instanceof Map<?, ?>)) {
            throw new MapperParsingException("Unable to parse CorrelationParamsContext");
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> contextMap = (Map<String, Object>) in;
        VectorSimilarityFunction similarityFunction = VectorSimilarityFunction.EUCLIDEAN;
        Map<String, Object> parameters = new HashMap<>();

        for (Map.Entry<String, Object> contextEntry: contextMap.entrySet()) {
            String key = contextEntry.getKey();
            Object value = contextEntry.getValue();

            if (VECTOR_SIMILARITY_FUNCTION.equals(key)) {
                if (value != null && !(value instanceof String)) {
                    throw new MapperParsingException(String.format(Locale.getDefault(), "%s must be a string", VECTOR_SIMILARITY_FUNCTION));
                }

                try {
                    similarityFunction = VectorSimilarityFunction.valueOf((String) value);
                } catch (IllegalArgumentException ex) {
                    throw new MapperParsingException(String.format(Locale.getDefault(), "Invalid %s: %s", VECTOR_SIMILARITY_FUNCTION, value));
                }
            } else if (PARAMETERS.equals(key)) {
                if (value == null) {
                    parameters = null;
                    continue;
                }

                if (!(value instanceof Map)) {
                    throw new MapperParsingException("Unable to parse parameters for Correlation context");
                }

                @SuppressWarnings("unchecked")
                Map<String, Object> valueMap = (Map<String, Object>) value;
                assert parameters != null;
                parameters.putAll(valueMap);
            } else {
                throw new MapperParsingException(String.format(Locale.getDefault(), "Invalid parameter for : %s", key));
            }
        }
        return new CorrelationParamsContext(similarityFunction, parameters);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(VECTOR_SIMILARITY_FUNCTION, similarityFunction.name());
        if (params == null) {
            builder.field(PARAMETERS, (String) null);
        } else {
            builder.startObject(PARAMETERS);
            for (Map.Entry<String, Object> parameter: parameters.entrySet()) {
                builder.field(parameter.getKey(), parameter.getValue());
            }
            builder.endObject();
        }
        builder.endObject();
        return builder;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelationParamsContext that = (CorrelationParamsContext) o;
        return similarityFunction == that.similarityFunction && parameters.equals(that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(similarityFunction, parameters);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(similarityFunction.name());
        if (this.parameters != null) {
            out.writeMap(parameters);
        }
    }

    public VectorSimilarityFunction getSimilarityFunction() {
        return similarityFunction;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }
}