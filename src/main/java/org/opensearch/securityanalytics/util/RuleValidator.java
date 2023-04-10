/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.opensearch.action.ActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.GetMappingsViewRequest;
import org.opensearch.securityanalytics.action.GetMappingsViewResponse;
import org.opensearch.securityanalytics.action.SearchRuleAction;
import org.opensearch.securityanalytics.action.SearchRuleRequest;
import org.opensearch.securityanalytics.mapper.MapperUtils;
import org.opensearch.securityanalytics.model.Rule;

public class RuleValidator
{
    private final static int MAX_RULES_TO_VALIDATE = 1000;

    private final static String RULE_ID = "_id";

    private final Client client;
    private final NamedXContentRegistry namedXContentRegistry;

    public RuleValidator(Client client, NamedXContentRegistry namedXContentRegistry) {
        this.client = client;
        this.namedXContentRegistry = namedXContentRegistry;
    }

    public void validateCustomRules(List<String> ruleIds, String indexName, ActionListener<List<String>> listener) {

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.fetchSource(FetchSourceContext.FETCH_SOURCE);

        QueryBuilder queryBuilder = QueryBuilders.termsQuery( RULE_ID, ruleIds.toArray(new String[]{}));
        SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                .source(new SearchSourceBuilder()
                        .seqNoAndPrimaryTerm(false)
                        .version(false)
                        .query(queryBuilder)
                        .fetchSource(FetchSourceContext.FETCH_SOURCE)
                        .size(MAX_RULES_TO_VALIDATE)
                )
                .indices(Rule.CUSTOM_RULES_INDEX);

        StepListener<SearchResponse> searchRuleResponseListener = new StepListener();
        searchRuleResponseListener.whenComplete(searchRuleResponse -> {

            List<Rule> rules = getRules(searchRuleResponse, namedXContentRegistry);
            validateRules(rules, indexName, listener);

        }, listener::onFailure);
        client.execute(SearchRuleAction.INSTANCE, new SearchRuleRequest(false, searchRequest), searchRuleResponseListener);
    }

    private void validateRules(List<Rule> rules, String indexName, ActionListener<List<String>> listener) {
        // Get index mappings
        String ruleTopic = rules.get(0).getCategory();
        StepListener<GetMappingsViewResponse> getMappingsViewResponseListener = new StepListener();
        getMappingsViewResponseListener.whenComplete(getMappingsViewResponse -> {

            List<String> nonapplicableRuleIds = new ArrayList<>();
            for(Rule r : rules) {
                // We will check against all index fields and applicable template aliases too
                List<String> allIndexFields = MapperUtils.extractAllFieldsFlat(getMappingsViewResponse.getAliasMappings());
                allIndexFields.addAll(getMappingsViewResponse.getUnmappedIndexFields());
                // check if all rule fields are present in index fields
                List<String> missingRuleFields = r.getQueryFieldNames()
                        .stream()
                        .map(e -> e.getValue())
                        .filter(e -> allIndexFields.contains(e) == false)
                        .collect(Collectors.toList());

                if (missingRuleFields.size() > 0) {
                    nonapplicableRuleIds.add(r.getId());
                }
            }
            listener.onResponse(nonapplicableRuleIds);
        }, listener::onFailure);
        client.execute(
                GetMappingsViewAction.INSTANCE,
                new GetMappingsViewRequest(indexName, ruleTopic),
                getMappingsViewResponseListener
        );
    }

    public static List<Rule> getRules(SearchResponse response, NamedXContentRegistry xContentRegistry) throws IOException {
        List<Rule> rules = new ArrayList<>((int) response.getHits().getTotalHits().value);
        for (SearchHit hit : response.getHits()) {
            XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry,
                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
            Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
            rules.add(rule);
        }
        return rules;
    }
}
