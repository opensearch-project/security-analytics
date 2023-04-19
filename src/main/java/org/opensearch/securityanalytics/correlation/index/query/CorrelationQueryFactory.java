/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.query;

import org.apache.lucene.search.KnnVectorQuery;
import org.apache.lucene.search.Query;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryShardContext;

import java.io.IOException;
import java.util.Optional;

public class CorrelationQueryFactory {

    public static Query create(CreateQueryRequest createQueryRequest) {
        final String indexName = createQueryRequest.getIndexName();
        final String fieldName = createQueryRequest.getFieldName();
        final int k = createQueryRequest.getK();
        final float[] vector = createQueryRequest.getVector();

        if (createQueryRequest.getFilter().isPresent()) {
            final QueryShardContext context = createQueryRequest.getContext().orElseThrow(
                    () -> new RuntimeException("Shard context cannot be null")
            );

            try {
                final Query filterQuery = createQueryRequest.getFilter().get().toQuery(context);
                return new KnnVectorQuery(fieldName, vector, k, filterQuery);
            } catch (IOException ex) {
                throw new RuntimeException("Cannot create knn query with filter", ex);
            }
        }
        return new KnnVectorQuery(fieldName, vector, k);
    }

    static class CreateQueryRequest {
        private String indexName;

        private String fieldName;

        private float[] vector;

        private int k;

        private QueryBuilder filter;

        private QueryShardContext context;

        public CreateQueryRequest(String indexName,
                                  String fieldName,
                                  float[] vector,
                                  int k,
                                  QueryBuilder filter,
                                  QueryShardContext context) {
            this.indexName = indexName;
            this.fieldName = fieldName;
            this.vector = vector;
            this.k = k;
            this.filter = filter;
            this.context = context;
        }

        public String getIndexName() {
            return indexName;
        }

        public String getFieldName() {
            return fieldName;
        }

        public float[] getVector() {
            return vector;
        }

        public int getK() {
            return k;
        }

        public Optional<QueryBuilder> getFilter() {
            return Optional.ofNullable(filter);
        }

        public Optional<QueryShardContext> getContext() {
            return Optional.ofNullable(context);
        }
    }
}