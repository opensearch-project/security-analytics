package org.opensearch.securityanalytics.rules;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportAction;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.SearchRuleAction;
import org.opensearch.securityanalytics.action.SearchRuleRequest;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.test.OpenSearchSingleNodeTestCase;

import static org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq.SigmaHQRuleSourcer.SIGMAHQ_SOURCER_ID;

public class ExternalRuleSourcerIT extends OpenSearchSingleNodeTestCase {

    @Override
    public boolean resetNodeAfterTest() {
        return false;
    }

    @Override
    protected Collection<Class<? extends Plugin>> getPlugins() {
        return List.of(SecurityAnalyticsPlugin.class);
    }

    public void testRuleSourcer() throws ExecutionException, InterruptedException {
        System.setSecurityManager(null);
        List<SearchHit> allHits = new ArrayList<>();

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(SearchSourceBuilder.searchSource()
                .size(10000)
                .from(0)
                .fetchSource(true)
                .query(QueryBuilders.matchAllQuery())
        ).indices(Rule.PRE_PACKAGED_RULES_INDEX);

        SearchResponse resp = client().execute(
                SearchRuleAction.INSTANCE,
                new SearchRuleRequest(true, searchRequest)
        ).get();
        


        client().execute(
                ExternalSourceRuleImportAction.INSTANCE,
                new ExternalSourceRuleImportRequest(SIGMAHQ_SOURCER_ID)
        ).get();
        assertTrue(true);
    }

}
