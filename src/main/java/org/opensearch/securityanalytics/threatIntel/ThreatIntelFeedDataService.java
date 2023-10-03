package org.opensearch.securityanalytics.threatIntel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.findings.FindingsService;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Service to handle CRUD operations on Threat Intel Feed Data
 */
public class ThreatIntelFeedDataService {
    private static final Logger log = LogManager.getLogger(FindingsService.class);

    public static void getThreatIntelFeedData(ClusterState state, Client client, IndexNameExpressionResolver indexNameExpressionResolver,
                                       String feedName, String iocType,
                                       ActionListener<List<ThreatIntelFeedData>> listener, NamedXContentRegistry xContentRegistry) {
        String indexPattern = String.format(".opendsearch-sap-threatintel-%s*", feedName);
        String tifdIndex = IndexUtils.getNewIndexByCreationDate(state, indexNameExpressionResolver, indexPattern);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("ioc_type", iocType)));
        SearchRequest searchRequest = new SearchRequest(tifdIndex);
        searchRequest.source().size(9999); //TODO: convert to scroll
        searchRequest.source(sourceBuilder);
        client.search(searchRequest, ActionListener.wrap(r -> listener.onResponse(getTifdList(r, xContentRegistry)), e -> {
            log.error(String.format(
                    "Failed to fetch threat intel feed data %s from system index %s", feedName, tifdIndex), e);
            listener.onFailure(e);
        }));
    }

    private static List<ThreatIntelFeedData> getTifdList(SearchResponse searchResponse, NamedXContentRegistry xContentRegistry) {
        List<ThreatIntelFeedData> list = new ArrayList<>();
        if (searchResponse.getHits().getHits().length != 0) {
            Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
                try {
                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                            xContentRegistry,
                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                    );
                    list.add(ThreatIntelFeedData.parse(xcp, hit.getId(), hit.getVersion()));
                } catch (Exception e) {
                    log.error(() ->
                            new ParameterizedMessage("Failed to parse Threat intel feed data doc from hit {}", hit), e);
                }

            });
        }
        return list;
    }
}
