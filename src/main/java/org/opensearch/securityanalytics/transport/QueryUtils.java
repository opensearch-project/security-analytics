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
import org.opensearch.index.query.functionscore.FunctionScoreQueryBuilder;

import java.util.List;

/**
 * Utility methods for inspecting query trees for security-sensitive patterns.
 * Uses manual instanceof traversal to walk all sub-queries, ensuring complete
 * coverage of compound query types. Unrecognized query types are denied by default
 * (treated as potentially containing terms lookup) for forward-compatible safety.
 */
public class QueryUtils {

    private QueryUtils() {}

    /**
     * Checks if a query tree contains any TermsQueryBuilder with a termsLookup
     * (i.e., a cross-index terms lookup that could be used to probe data in unauthorized indices).
     * Traverses compound queries manually via instanceof checks.
     * Unrecognized/opaque query types are treated as unsafe (returns true) to deny by default.
     */
    public static boolean containsTermsLookup(QueryBuilder query) {
        if (query == null) {
            return false;
        }

        // Direct check for TermsQueryBuilder with termsLookup
        if (query instanceof TermsQueryBuilder) {
            return ((TermsQueryBuilder) query).termsLookup() != null;
        }

        // Recurse into known compound query types
        if (query instanceof BoolQueryBuilder) {
            BoolQueryBuilder boolQuery = (BoolQueryBuilder) query;
            for (QueryBuilder clause : boolQuery.must()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : boolQuery.mustNot()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : boolQuery.should()) {
                if (containsTermsLookup(clause)) return true;
            }
            for (QueryBuilder clause : boolQuery.filter()) {
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

        if (query instanceof FunctionScoreQueryBuilder) {
            return containsTermsLookup(((FunctionScoreQueryBuilder) query).query());
        }

        // Leaf query types that cannot contain sub-queries or terms lookups are safe.
        // Known safe leaves: MatchAllQueryBuilder, MatchQueryBuilder, TermQueryBuilder,
        // RangeQueryBuilder, ExistsQueryBuilder, WildcardQueryBuilder, PrefixQueryBuilder,
        // RegexpQueryBuilder, FuzzyQueryBuilder, IdsQueryBuilder, MatchPhraseQueryBuilder, etc.
        // For any unrecognized compound type, deny by default for safety.
        String queryName = query.getName();
        if (isKnownSafeLeaf(queryName)) {
            return false;
        }

        // Unrecognized query type — deny by default
        return true;
    }

    private static boolean isKnownSafeLeaf(String queryName) {
        switch (queryName) {
            case "match_all":
            case "match_none":
            case "match":
            case "match_phrase":
            case "match_phrase_prefix":
            case "multi_match":
            case "term":
            case "range":
            case "exists":
            case "wildcard":
            case "prefix":
            case "regexp":
            case "fuzzy":
            case "ids":
            case "type":
            case "query_string":
            case "simple_query_string":
            case "span_term":
            case "span_first":
            case "span_near":
            case "span_or":
            case "span_not":
            case "span_containing":
            case "span_within":
            case "span_multi":
            case "more_like_this":
            case "common":
            case "geo_bounding_box":
            case "geo_distance":
            case "geo_polygon":
            case "geo_shape":
            case "script":
            case "percolate":
            case "wrapper":
            case "match_bool_prefix":
                return true;
            default:
                return false;
        }
    }
}
