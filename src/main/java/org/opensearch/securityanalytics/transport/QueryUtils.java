/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.lucene.search.BooleanClause;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.GeoShapeQueryBuilder;
import org.opensearch.index.query.MoreLikeThisQueryBuilder;
import org.opensearch.index.query.QueryBuilderVisitor;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.index.query.WrapperQueryBuilder;

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

    /**
     * Checks if a query tree fetches documents while it is rewritten: a terms lookup, a more like this query with like or
     * unlike documents, a geo shape query with an indexed shape, or a percolate query. A wrapper query is counted too,
     * because its inner query is not visible until it is rewritten.
     *
     * @param query the query to check, or null
     * @return true when the query reads documents other than the ones it searches
     */
    public static boolean containsDocumentFetch(QueryBuilder query) {
        if (query == null) {
            return false;
        }
        DocumentFetchDetector detector = new DocumentFetchDetector();
        query.visit(detector);
        return detector.found;
    }

    private static class DocumentFetchDetector implements QueryBuilderVisitor {
        boolean found = false;

        @Override
        public void accept(QueryBuilder qb) {
            if (qb instanceof TermsQueryBuilder terms && terms.termsLookup() != null) {
                found = true;
            } else if (qb instanceof MoreLikeThisQueryBuilder mlt && (mlt.likeItems().length > 0 || mlt.unlikeItems().length > 0)) {
                found = true;
            } else if (qb instanceof GeoShapeQueryBuilder geoShape && geoShape.indexedShapeId() != null) {
                found = true;
            } else if (qb instanceof WrapperQueryBuilder || "percolate".equals(qb.getWriteableName())) {
                // The percolator module is not on this plugin's classpath, so the query is matched by name.
                found = true;
            }
        }

        @Override
        public QueryBuilderVisitor getChildVisitor(BooleanClause.Occur occur) {
            return this;
        }
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
