/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.BoostingQueryBuilder;
import org.opensearch.index.query.ConstantScoreQueryBuilder;
import org.opensearch.index.query.DisMaxQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.TermsQueryBuilder;

/**
 * Utility methods for inspecting query trees for security-sensitive patterns.
 * Uses manual instanceof traversal to walk all sub-queries, ensuring complete
 * coverage of known compound query types. Unknown query types are denied by default
 * (treated as potentially containing terms lookups) to prevent bypass via novel wrappers.
 */
public class QueryUtils {

    private QueryUtils() {}

    /**
     * Checks if a query tree contains any TermsQueryBuilder with a termsLookup
     * (i.e., a cross-index terms lookup that could be used to probe data in unauthorized indices).
     * Traverses known compound query types recursively; denies unknown compound types by default.
     */
    public static boolean containsTermsLookup(QueryBuilder query) {
        if (query == null) {
            return false;
        }

        // Check if this is a TermsQueryBuilder with a termsLookup
        if (query instanceof TermsQueryBuilder) {
            return ((TermsQueryBuilder) query).termsLookup() != null;
        }

        // Recurse into known compound query types
        if (query instanceof BoolQueryBuilder) {
            BoolQueryBuilder bool = (BoolQueryBuilder) query;
            for (QueryBuilder clause : bool.must()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : bool.should()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : bool.mustNot()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : bool.filter()) {
                if (containsTermsLookup(clause)) return true;
            }
            return false;
        }

        if (query instanceof ConstantScoreQueryBuilder) {
            return containsTermsLookup(((ConstantScoreQueryBuilder) query).innerQuery());
        }

        if (query instanceof BoostingQueryBuilder) {
            BoostingQueryBuilder boosting = (BoostingQueryBuilder) query;
            return containsTermsLookup(boosting.positiveQuery()) || containsTermsLookup(boosting.negativeQuery());
        }

        if (query instanceof DisMaxQueryBuilder) {
            for (QueryBuilder clause : ((DisMaxQueryBuilder) query).innerQueries()) {
                if (containsTermsLookup(clause)) return true;
            }
            return false;
        }

        if (query instanceof NestedQueryBuilder) {
            return containsTermsLookup(((NestedQueryBuilder) query).query());
        }

        // For all other (leaf) query types, they cannot contain a terms lookup
        return false;
    }
}
