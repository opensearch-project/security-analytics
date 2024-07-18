package org.opensearch.securityanalytics.threatIntel.model.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.action.DocLevelMonitorFanOutRequest;
import org.opensearch.commons.alerting.action.DocLevelMonitorFanOutResponse;
import org.opensearch.commons.alerting.model.DocumentLevelTriggerRunResult;
import org.opensearch.commons.alerting.model.InputRunResults;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.MonitorRunResult;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.commons.alerting.util.AlertingException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;
import org.opensearch.securityanalytics.threatIntel.iocscan.service.SaIoCScanService;
import org.opensearch.securityanalytics.threatIntel.iocscan.service.ThreatIntelMonitorRunner;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import static org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils.getThreatIntelInputFromBytesReference;
import static org.opensearch.securityanalytics.util.IndexUtils.getConcreteindexToMonitorInputIndicesMap;

public class TransportThreatIntelMonitorFanOutAction extends HandledTransportAction<DocLevelMonitorFanOutRequest, DocLevelMonitorFanOutResponse> {
    private static final Logger log = LogManager.getLogger(TransportThreatIntelMonitorFanOutAction.class);
    private final ClusterService clusterService;

    private final Settings settings;
    private final SATIFSourceConfigService saTifSourceConfigService;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;
    private final SaIoCScanService saIoCScanService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    @Inject
    public TransportThreatIntelMonitorFanOutAction(
            TransportService transportService,
            Client client,
            NamedXContentRegistry xContentRegistry,
            ClusterService clusterService,
            Settings settings,
            ActionFilters actionFilters,
            SATIFSourceConfigService saTifSourceConfigService,
            SaIoCScanService saIoCScanService,
            IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        super(ThreatIntelMonitorRunner.FAN_OUT_ACTION_NAME, transportService, actionFilters, DocLevelMonitorFanOutRequest::new);
        this.clusterService = clusterService;
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.settings = settings;
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.saIoCScanService = saIoCScanService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
    }

    @Override
    protected void doExecute(Task task, DocLevelMonitorFanOutRequest request, ActionListener<DocLevelMonitorFanOutResponse> actionListener) {
        try {
            Monitor monitor = request.getMonitor();
            MonitorRunResult<DocumentLevelTriggerRunResult> monitorResult = new MonitorRunResult<>(
                    monitor.getName(),
                    Instant.now(),
                    Instant.now(),
                    null,
                    new InputRunResults(Collections.emptyList(), null, null),
                    Collections.emptyMap()
            );

            // fetch list of threat intel data containing indices per indicator type

            saTifSourceConfigService.getIocTypeToIndices(ActionListener.wrap(
                    iocTypeToIndicesMap -> {
                        onGetIocTypeToIndices(iocTypeToIndicesMap, request, actionListener);
                    }, e -> {
                        log.error(() -> new ParameterizedMessage("Unexpected Failure in threat intel monitor {} fan out action", request.getMonitor().getId()), e);
                        actionListener.onResponse(
                                new DocLevelMonitorFanOutResponse(
                                        clusterService.localNode().getId(),
                                        request.getExecutionId(),
                                        request.getMonitor().getId(),
                                        request.getMonitorMetadata().getLastRunContext(),
                                        new InputRunResults(Collections.emptyList(), null, null),
                                        Collections.emptyMap(),//TODO trigger results,
                                        new AlertingException("Fan action of threat intel monitor failed", RestStatus.INTERNAL_SERVER_ERROR, e)
                                )
                        );
                    }
            ));

        } catch (Exception ex) {
            log.error(() -> new ParameterizedMessage("Unexpected Failure in threat intel monitor {} fan out action", request.getMonitor().getId()), ex);
            actionListener.onFailure(ex);
        }
    }

    private void onGetIocTypeToIndices(Map<String, List<String>> iocTypeToIndicesMap, DocLevelMonitorFanOutRequest request, ActionListener<DocLevelMonitorFanOutResponse> actionListener) throws IOException {
        RemoteDocLevelMonitorInput remoteDocLevelMonitorInput = (RemoteDocLevelMonitorInput) request.getMonitor().getInputs().get(0);
        List<String> indices = remoteDocLevelMonitorInput.getDocLevelMonitorInput().getIndices();
        ThreatIntelInput threatIntelInput = getThreatIntelInputFromBytesReference(remoteDocLevelMonitorInput.getInput(), xContentRegistry);
        // TODO update fanout request to add mapping of monitor.input.indices' index to concrete index name.
        //  right now we can't say which one of aliases/index pattern has resolved to this concrete index name
        //
        //  Map<String, List<String>> fieldsToFetchPerIndex = new HashMap<>(); alias -> fields mapping is given but we have concrete index name
        List<String> fieldsToFetch = new ArrayList<>();
        threatIntelInput.getPerIocTypeScanInputList().forEach(perIocTypeScanInput -> {
            perIocTypeScanInput.getIndexToFieldsMap().values().forEach(fieldsToFetch::addAll);
//            Map<String, List<String>> indexToFieldsMapPerInput = perIocTypeScanInput.getIndexToFieldsMap();
//            for (String index : indexToFieldsMapPerInput.keySet()) {
//                List<String> strings = fieldsToFetchPerIndex.computeIfAbsent(
//                        perIocTypeScanInput.getIocType(),
//                        k -> new ArrayList<>());
//                strings.addAll(indexToFieldsMapPerInput.get(index));
//            }
        });

        // function passed to update last run context with new max sequence number
//        Map<String, Object> updatedLastRunContext = request.getIndexExecutionContext().getUpdatedLastRunContext();
        Map<String, Object> updatedLastRunContext = request.getMonitorMetadata().getLastRunContext();
        BiConsumer<ShardId, String> lastRunContextUpdateConsumer = (shardId, value) -> {
            String indexName = shardId.getIndexName();
            if (updatedLastRunContext.containsKey(indexName)) {
                HashMap<String, Object> context = (HashMap<String, Object>) updatedLastRunContext.putIfAbsent(indexName, new HashMap<String, Object>());
                context.put(String.valueOf(shardId.getId()), value);
            } else {
                log.error("monitor metadata for threat intel monitor {} expected to contain last run context for index {}",
                        request.getMonitor().getId(), indexName);
            }
        };
        ActionListener<List<SearchHit>> searchHitsListener = ActionListener.wrap(
                (List<SearchHit> hits) -> {
                    BiConsumer<Object, Exception> resultConsumer = (r, e) -> {
                        if (e == null) {
                            actionListener.onResponse(
                                    new DocLevelMonitorFanOutResponse(
                                            clusterService.localNode().getId(),
                                            request.getExecutionId(),
                                            request.getMonitor().getId(),
                                            updatedLastRunContext,
                                            new InputRunResults(Collections.emptyList(), null, null),
                                            Collections.emptyMap(),//TODO trigger results,
                                            null
                                    )
                            );
                        } else {
                            actionListener.onFailure(e);
                        }
                    };
                    Map<String, List<String>> concreteindexToMonitorInputIndicesMap = getConcreteindexToMonitorInputIndicesMap(
                            remoteDocLevelMonitorInput.getDocLevelMonitorInput().getIndices(),
                            clusterService,
                            indexNameExpressionResolver);
                    saIoCScanService.scanIoCs(new IocScanContext<>(
                            request.getMonitor(),
                            request.getMonitorMetadata(),
                            false,
                            hits,
                            threatIntelInput,
                            indices,
                            iocTypeToIndicesMap,
                            concreteindexToMonitorInputIndicesMap
                    ), resultConsumer);
                },
                e -> {
                    log.error("unexpected error while", e);
                    actionListener.onFailure(e);
                }
        );
        fetchDataFromShards(request,
                fieldsToFetch,
                lastRunContextUpdateConsumer,
                searchHitsListener);
    }

    private void fetchDataFromShards(
            DocLevelMonitorFanOutRequest request,
            List<String> fieldsToFetch,
            BiConsumer<ShardId, String> updateLastRunContext,
            ActionListener<List<SearchHit>> searchHitsListener) {
        if (request.getShardIds().isEmpty())
            return;
        GroupedActionListener<SearchHitsOrException> searchHitsFromAllShardsListener = new GroupedActionListener<>(
                ActionListener.wrap(
                        searchHitsOrExceptionCollection -> {
                            List<SearchHit> hits = new ArrayList<>();
                            for (SearchHitsOrException searchHitsOrException : searchHitsOrExceptionCollection) {
                                if (searchHitsOrException.exception == null) {
                                    hits.addAll(searchHitsOrException.hits);
                                } // else not logging exception as groupedListener onResponse() will log error message
                            }
                            searchHitsListener.onResponse(hits);
                        }, e -> {
                            log.error("unexpected failure while fetch documents for threat intel monitor " + request.getMonitor().getId(), e);
                            searchHitsListener.onResponse(Collections.emptyList());
                        }
                ), request.getShardIds().size()
        );
        for (ShardId shardId : request.getShardIds()) {
            String shard = shardId.getId() + "";
            Map<String, Object> lastRunContext = request.getMonitorMetadata().getLastRunContext();
            if (lastRunContext.containsKey(shardId.getIndexName()) && lastRunContext.get(shardId.getIndexName()) instanceof Map) {
                HashMap<String, Object> shardLastSeenMapForIndex = (HashMap<String, Object>) lastRunContext.get(shardId.getIndexName());
                Long prevSeqNo = shardLastSeenMapForIndex.get(shard) != null ? Long.parseLong(shardLastSeenMapForIndex.get(shard).toString()) : null;
                long fromSeqNo = prevSeqNo != null ? prevSeqNo : SequenceNumbers.NO_OPS_PERFORMED;
                long toSeqNo = Long.MAX_VALUE;
                fetchLatestDocsFromShard(shardId, fromSeqNo, toSeqNo, new ArrayList<>(), request.getMonitor(), shardLastSeenMapForIndex, updateLastRunContext, fieldsToFetch, searchHitsFromAllShardsListener);
            }

        }
    }

    /**
     * recursive function to keep fetching docs in batches of 10000 per search request. all docs with seq_no greater than
     * the last seen seq_no are fetched in descending order of sequence number.
     */

    private void fetchLatestDocsFromShard(
            ShardId shardId,
            long fromSeqNo, long toSeqNo, List<SearchHit> searchHitsSoFar, Monitor monitor,
            Map<String, Object> shardLastSeenMapForIndex,
            BiConsumer<ShardId, String> updateLastRunContext,
            List<String> fieldsToFetch,
            GroupedActionListener<SearchHitsOrException> listener) {

        String shard = shardId.getId() + "";
        try {
            if (toSeqNo <= fromSeqNo || toSeqNo < 0) {
                listener.onResponse(new SearchHitsOrException(searchHitsSoFar, null));
                return;
            }
            Long prevSeqNo = shardLastSeenMapForIndex.get(shard) != null ? Long.parseLong(shardLastSeenMapForIndex.get(shard).toString()) : null;
            if (toSeqNo > fromSeqNo) {

                searchShard(
                        shardId.getIndexName(),
                        shard,
                        fromSeqNo,
                        toSeqNo,
                        Collections.emptyList(),
                        fieldsToFetch,
                        ActionListener.wrap(
                                hits -> {
                                    if (hits.getHits().length == 0) {
                                        if (toSeqNo == Long.MAX_VALUE) { // didn't find any docs
                                            updateLastRunContext.accept(shardId, prevSeqNo != null ? prevSeqNo.toString() : SequenceNumbers.NO_OPS_PERFORMED + "");
                                        }
                                        listener.onResponse(new SearchHitsOrException(searchHitsSoFar, null));
                                        return;
                                    }
                                    searchHitsSoFar.addAll(Arrays.asList(hits.getHits()));
                                    if (toSeqNo == Long.MAX_VALUE) { // max sequence number of shard needs to be computed
                                        updateLastRunContext.accept(shardId, String.valueOf(hits.getHits()[0].getSeqNo()));
                                    }

                                    long leastSeqNoFromHits = hits.getHits()[hits.getHits().length - 1].getSeqNo();
                                    long updatedToSeqNo = leastSeqNoFromHits - 1;
                                    // recursive call to fetch docs with updated seq no.
                                    fetchLatestDocsFromShard(shardId, fromSeqNo, updatedToSeqNo, searchHitsSoFar, monitor, shardLastSeenMapForIndex, updateLastRunContext, fieldsToFetch, listener);
                                }, e -> {
                                    log.error(() -> new ParameterizedMessage("Threat intel Monitor {}: Failed to search shard {} in index {}", monitor.getId(), shard, shardId.getIndexName()), e);
                                    listener.onResponse(new SearchHitsOrException(searchHitsSoFar, e));
                                }
                        )
                );
            }
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("threat intel Monitor {}: Failed to run fetch data from shard [{}] of index [{}]",
                    monitor.getId(), shardId, shardId.getIndexName()), e);
            listener.onResponse(new SearchHitsOrException(searchHitsSoFar, e));
        }
    }

    public void searchShard(
            String index,
            String shard,
            Long prevSeqNo,
            long maxSeqNo,
            List<String> docIds,
            List<String> fieldsToFetch,
            ActionListener<SearchHits> listener) {

        if (prevSeqNo != null && prevSeqNo.equals(maxSeqNo) && maxSeqNo != 0L) {
            log.debug("Sequence number unchanged.");
            listener.onResponse(SearchHits.empty());
        }

        BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery()
                .filter(QueryBuilders.rangeQuery("_seq_no").gt(prevSeqNo).lte(maxSeqNo));

        if (docIds != null && !docIds.isEmpty()) {
            boolQueryBuilder.filter(QueryBuilders.termsQuery("_id", docIds));
        }

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .version(true)
                .sort("_seq_no", SortOrder.DESC)
                .seqNoAndPrimaryTerm(true)
                .query(boolQueryBuilder)
                .size(10000);

        if (!fieldsToFetch.isEmpty()) {
            searchSourceBuilder.fetchSource(false);
            for (String field : fieldsToFetch) {
                searchSourceBuilder.fetchField(field);
            }
        }

        SearchRequest request = new SearchRequest()
                .indices(index)
                .preference("_shards:" + shard)
                .source(searchSourceBuilder);

        client.search(request, ActionListener.wrap(
                response -> {
                    if (response.status() != RestStatus.OK) {
                        log.error("Fetching docs from shard failed");
                        throw new IOException("Failed to search shard: [" + shard + "] in index [" + index + "]. Response status is " + response.status());
                    }
                    listener.onResponse(response.getHits());
                },
                listener::onFailure // exception logged in invoker method
        ));

    }

    public static class SearchHitsOrException {
        private final List<SearchHit> hits;
        private final Exception exception;

        public SearchHitsOrException(List<SearchHit> hits, Exception exception) {
            assert hits == null || hits.isEmpty() || exception == null; // just a verification that only one of the variables is non-null
            this.hits = hits;
            this.exception = exception;
        }

        public List<SearchHit> getHits() {
            return hits;
        }

        public Exception getException() {
            return exception;
        }
    }
}