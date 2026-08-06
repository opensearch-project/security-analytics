/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.lucene.search.BooleanClause;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.TermsQueryBuilder;

/**
 * Utility methods for inspecting query trees for security-sensitive patterns.
 * Uses the framework's QueryBuilderVisitor to traverse all sub-queries generically,
 * ensuring complete coverage of all query types including future additions.
 */
public class QueryUtils {

    private QueryUtils() {}

    /**
     * Checks if a query tree contains any TermsQueryBuilder with a termsLookup
     * (i.e., a cross-index terms lookup that could be used to probe data in unauthorized indices).
     * Uses QueryBuilder.visit() for complete traversal of all query types.
     */
    public static boolean containsTermsLookup(QueryBuilder query) {
        if (query == null) {
            return false;
        }

        TermsLookupDetector detector = new TermsLookupDetector();
        query.visit(detector);
        return detector.found;
    }

    private static class TermsLookupDetector implements QueryBuilderVisitor {
        boolean found = false;

        @Override
        public void accept(QueryBuilder qb) {
            if (qb instanceof TermsQueryBuilder) {
                if (((TermsQueryBuilder) qb).termsLookup() != null) {
                    found = true;
                }
            }
        }

        @Override
        public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
            return this;
        }
    }
}
