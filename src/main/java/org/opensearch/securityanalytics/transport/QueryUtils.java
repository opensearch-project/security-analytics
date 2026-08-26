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

public class QueryUtils {
    private QueryUtils() {}

    public static boolean containsTermsLookup(QueryBuilder query) {
        if (query == null) return false;
        if (query instanceof TermsQueryBuilder) {
            return ((TermsQueryBuilder) query).termsLookup() != null;
        }
        if (query instanceof BoolQueryBuilder) {
            BoolQueryBuilder bq = (BoolQueryBuilder) query;
            return check(bq.must()) || check(bq.should()) || check(bq.filter()) || check(bq.mustNot());
        }
        if (query instanceof ConstantScoreQueryBuilder) return containsTermsLookup(((ConstantScoreQueryBuilder) query).innerQuery());
        if (query instanceof BoostingQueryBuilder) {
            BoostingQueryBuilder b = (BoostingQueryBuilder) query;
            return containsTermsLookup(b.positiveQuery()) || containsTermsLookup(b.negativeQuery());
        }
        if (query instanceof DisMaxQueryBuilder) return check(((DisMaxQueryBuilder) query).innerQueries());
        if (query instanceof NestedQueryBuilder) return containsTermsLookup(((NestedQueryBuilder) query).query());
        if (query instanceof FunctionScoreQueryBuilder) {
            FunctionScoreQueryBuilder fsq = (FunctionScoreQueryBuilder) query;
            if (containsTermsLookup(fsq.query())) return true;
            for (FunctionScoreQueryBuilder.FilterFunctionBuilder ffb : fsq.filterFunctionBuilders()) {
                if (containsTermsLookup(ffb.getFilter())) return true;
            }
            return false;
        }
        // Deny by default for unrecognized types
        return true;
    }

    private static boolean check(List<QueryBuilder> queries) {
        if (queries == null) return false;
        for (QueryBuilder q : queries) { if (containsTermsLookup(q)) return true; }
        return false;
    }
}
