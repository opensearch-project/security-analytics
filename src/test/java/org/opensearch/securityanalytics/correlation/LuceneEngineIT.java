/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.apache.lucene.index.VectorSimilarityFunction;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.common.Strings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.correlation.index.CorrelationParamsContext;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class LuceneEngineIT extends SecurityAnalyticsRestTestCase {

    private static final int DIMENSION = 3;
    private static final String PROPERTIES_FIELD_NAME = "properties";
    private static final String TYPE_FIELD_NAME = "type";
    private static final String SECURITY_ANALYTICS_VECTOR_TYPE = "sa_vector";
    private static final String DIMENSION_FIELD_NAME = "dimension";
    private static final int M = 16;
    private static final int EF_CONSTRUCTION = 128;
    private static final String INDEX_NAME = "test-index-1";
    private static final Float[][] TEST_VECTORS = new Float[][]{{ 1.0f, 1.0f, 1.0f }, { 2.0f, 2.0f, 2.0f }, { 3.0f, 3.0f, 3.0f }};
    private static final float[][] TEST_QUERY_VECTORS = new float[][]{ { 1.0f, 1.0f, 1.0f }, { 2.0f, 2.0f, 2.0f }, { 3.0f, 3.0f, 3.0f } };
    private static final Map<VectorSimilarityFunction, Function<Float, Float>> VECTOR_SIMILARITY_TO_SCORE = Map.of(
            VectorSimilarityFunction.EUCLIDEAN,
            (similarity) -> 1 / (1 + similarity),
            VectorSimilarityFunction.DOT_PRODUCT,
            (similarity) -> (1 + similarity) / 2,
            VectorSimilarityFunction.COSINE,
            (similarity) -> (1 + similarity) / 2
    );

    @SuppressWarnings("unchecked")
    public void testQuery() throws IOException {
        String textField = "text-field";
        String luceneField = "lucene-field";
        XContentBuilder builder = XContentFactory.jsonBuilder()
                .startObject()
                .startObject(PROPERTIES_FIELD_NAME)
                .startObject(textField)
                .field(TYPE_FIELD_NAME, "text")
                .endObject()
                .startObject(luceneField)
                .field(TYPE_FIELD_NAME, SECURITY_ANALYTICS_VECTOR_TYPE)
                .field(DIMENSION_FIELD_NAME, DIMENSION)
                .startObject(CorrelationConstants.CORRELATION_CONTEXT)
                .field(CorrelationParamsContext.VECTOR_SIMILARITY_FUNCTION, VectorSimilarityFunction.EUCLIDEAN.name())
                .startObject(CorrelationParamsContext.PARAMETERS)
                .field(CorrelationConstants.METHOD_PARAMETER_M, M)
                .field(CorrelationConstants.METHOD_PARAMETER_EF_CONSTRUCTION, EF_CONSTRUCTION)
                .endObject()
                .endObject()
                .endObject()
                .endObject()
                .endObject();

        String mapping = Strings.toString(builder);
        createTestIndexWithMappingJson(client(), INDEX_NAME, mapping, getCorrelationDefaultIndexSettings());

        for (int idx = 0; idx < TEST_VECTORS.length; ++idx) {
            addCorrelationDoc(INDEX_NAME,
                    String.valueOf(idx+1),
                    List.of(textField, luceneField),
                    List.of(java.util.UUID.randomUUID().toString(), TEST_VECTORS[idx]));
        }
        refreshAllIndices();
        Assert.assertEquals(TEST_VECTORS.length, getDocCount(INDEX_NAME));

        int k = 2;
        for (float[] query: TEST_QUERY_VECTORS) {
            Response response = searchCorrelationIndex(INDEX_NAME, new CorrelationQueryBuilder(luceneField, query, k), k);
            Map<String, Object> responseBody = entityAsMap(response);
            Assert.assertEquals(2, ((List<Object>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).size());
            @SuppressWarnings("unchecked")
            double actualScore1 = Double.parseDouble(((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).get(0).get("_score").toString());
            @SuppressWarnings("unchecked")
            double actualScore2 = Double.parseDouble(((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).get(1).get("_score").toString());
            @SuppressWarnings("unchecked")
            List<Float> hit1 = ((Map<String, List<Double>>) ((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).get(0).get("_source")).get(luceneField).stream()
                            .map(Double::floatValue).collect(Collectors.toList());
            float[] resultVector1 = new float[hit1.size()];
            for (int i = 0; i < hit1.size(); ++i) {
                resultVector1[i] = hit1.get(i);
            }

            @SuppressWarnings("unchecked")
            List<Float> hit2 = ((Map<String, List<Double>>) ((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).get(1).get("_source")).get(luceneField).stream()
                    .map(Double::floatValue).collect(Collectors.toList());
            float[] resultVector2 = new float[hit2.size()];
            for (int i = 0; i < hit2.size(); ++i) {
                resultVector2[i] = hit2.get(i);
            }

            double rawScore1 = VectorSimilarityFunction.EUCLIDEAN.compare(resultVector1, query);
            Assert.assertEquals(rawScore1, actualScore1, 0.0001);
            double rawScore2 = VectorSimilarityFunction.EUCLIDEAN.compare(resultVector2, query);
            Assert.assertEquals(rawScore2, actualScore2, 0.0001);
        }
    }
}