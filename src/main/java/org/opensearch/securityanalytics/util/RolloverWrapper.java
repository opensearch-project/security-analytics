package org.opensearch.securityanalytics.util;

import java.util.Map;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.admin.indices.stats.IndicesStatsRequest;
import org.opensearch.client.Client;

public class RolloverWrapper {

    private Client client;

    public RolloverWrapper(Client client) {
        this.client = client;
    }

    public void rolloverIndex(RolloverRequestV2 request, ActionListener<RolloverResponse> listener) {
        if (request.minDocs != -1L) {
            getIndexDocCount(request.getRolloverTarget(), ActionListener.wrap(docCount -> {
                if (docCount < (request).minDocs) {
                    listener.onResponse(new RolloverResponse(null, null, Map.of("minDocs", false), false, false, false, false));
                } else {
                    client.admin().indices().rolloverIndex(request, listener);
                }
            }, listener::onFailure));
        } else {
            client.admin().indices().rolloverIndex(request, listener);
        }
    }

    private void getIndexDocCount(String index, ActionListener<Long> listener) {
        IndicesStatsRequest request = new IndicesStatsRequest()
                .indices(index)
                .docs(true);

        client.admin().indices().stats(request, ActionListener.wrap(r -> {
            listener.onResponse(r.getTotal().docs.getCount());
        }, listener::onFailure));
    }

    public static class RolloverRequestV2 extends RolloverRequest {

        private Long minDocs = -1L;

        public RolloverRequestV2(String rolloverTarget, String newIndexName) {
            super(rolloverTarget, newIndexName);
        }

        public void addMinIndexDocsCondition(Long minDocs) {
            this.minDocs = minDocs;
        }

    }

}
