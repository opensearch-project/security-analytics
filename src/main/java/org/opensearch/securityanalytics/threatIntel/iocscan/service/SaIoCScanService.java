package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.client.Client;
import org.opensearch.common.document.DocumentField;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.model.monitor.TransportThreatIntelMonitorFanOutAction.SearchHitsOrException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;

public class SaIoCScanService extends IoCScanService<SearchHit> {

    private static final Logger log = LogManager.getLogger(SaIoCScanService.class);
    public static final int MAX_TERMS = 65536; //make ioc index setting based. use same setting value to create index
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final IocFindingService iocFindingService;

    public SaIoCScanService(Client client, NamedXContentRegistry xContentRegistry, IocFindingService iocFindingService) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.iocFindingService = iocFindingService;
    }

    @Override
    void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocsPerType,
            Monitor monitor,
            BiConsumer<List<STIX2IOC>, Exception> callback,
            Map<String, List<String>> iocTypeToIndices) {
        long startTime = System.currentTimeMillis();
        int numIocs = iocsPerType.values().stream().mapToInt(Set::size).sum();
        GroupedActionListener<SearchHitsOrException> groupedListenerForAllIocTypes = getGroupedListenerForIocScanFromAllIocTypes(iocsPerType, monitor, callback, startTime, numIocs);
        for (String iocType : iocsPerType.keySet()) {
            List<String> indices = iocTypeToIndices.get(iocType);
            Set<String> iocs = iocsPerType.get(iocType);
              if (iocTypeToIndices.containsKey(iocType.toLowerCase())) {
                if (indices.isEmpty()) {
                    log.debug(
                            "Threat intel monitor {} : No ioc indices of type {} found so no scan performed.",
                            monitor.getId(),
                            iocType
                    );
                    groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(emptyList(), null));
                } else if (iocs.isEmpty()) {
                    log.debug(
                            "Threat intel monitor {} : No iocs of type {} found in user data so no scan performed.",
                            monitor.getId(),
                            iocType
                    );
                    groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(emptyList(), null));
                } else {
                    performScanForMaliciousIocsPerIocType(indices, iocs, monitor, iocType, groupedListenerForAllIocTypes);
                }
            } else {
                groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(emptyList(), null));
            }
        }
    }

    private GroupedActionListener<SearchHitsOrException> getGroupedListenerForIocScanFromAllIocTypes(Map<String, Set<String>> iocsPerType, Monitor monitor, BiConsumer<List<STIX2IOC>, Exception> callback, long startTime, int numIocs) {
        return new GroupedActionListener<>(
                ActionListener.wrap(
                        lists -> {
                            long endTime = System.currentTimeMillis();
                            long timetaken = endTime - startTime;
                            log.debug("IOC_SCAN: Threat intel monitor {} completed Ioc match phase in {} millis for {} iocs",
                                    monitor.getId(), timetaken, numIocs);
                            List<SearchHit> hits = new ArrayList<>();
                            lists.forEach(hitsOrException ->
                                    hits.addAll(hitsOrException.getHits() == null ?
                                            emptyList() :
                                            hitsOrException.getHits()));
                            List<STIX2IOC> iocs = new ArrayList<>();
                            hits.forEach(hit -> {
                                try {
                                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                                            xContentRegistry,
                                            LoggingDeprecationHandler.INSTANCE,
                                            hit.getSourceAsString());
                                    xcp.nextToken();

                                    STIX2IOC ioc = STIX2IOC.parse(xcp, hit.getId(), hit.getVersion());
                                    iocs.add(ioc);
                                } catch (Exception e) {
                                    log.error(() -> new ParameterizedMessage(
                                                    "Failed to parse IOC doc from hit {} index {}", hit.getId(), hit.getIndex()),
                                            e
                                    );
                                }
                            });
                            callback.accept(iocs, null);
                        },
                        e -> {
                            log.error("Threat intel monitor {} :Unexpected error while scanning data for malicious Iocs", e);
                            callback.accept(emptyList(), e);
                        }
                ),
                iocsPerType.size()
        );
    }

    private void performScanForMaliciousIocsPerIocType(
            List<String> indices,
            Set<String> iocs,
            Monitor monitor,
            String iocType,
            GroupedActionListener<SearchHitsOrException> listener) {
        // TODO change ioc indices max terms count to 100k and experiment
        // TODO add fuzzy postings on ioc value field to enable bloomfilter on iocs as an index data structure and benchmark performance
        GroupedActionListener<SearchHitsOrException> perIocTypeListener = getGroupedListenerForIocScanPerIocType(iocs, monitor, iocType, listener);
        List<String> iocList = new ArrayList<>(iocs);
        int totalIocs = iocList.size();

        for (int start = 0; start < totalIocs; start += MAX_TERMS) {
            int end = Math.min(start + MAX_TERMS, totalIocs);
            List<String> iocsSublist = iocList.subList(start, end);
            SearchRequest searchRequest = getSearchRequestForIocType(indices, iocType, iocsSublist);
            client.search(searchRequest, ActionListener.wrap(
                    searchResponse -> {
                        if (searchResponse.isTimedOut()) {
                            log.error("Threat intel monitor {} scan with {} user data indicators TIMED OUT for ioc Type {}",
                                    monitor.getId(),
                                    iocsSublist.size(),
                                    iocType
                            );
                        }
                        if (searchResponse.getFailedShards() > 0) {
                            for (ShardSearchFailure shardFailure : searchResponse.getShardFailures()) {
                                log.error("Threat intel monitor {} scan with {} user data indicators for ioc Type {} has Shard failures {}",
                                        monitor.getId(),
                                        iocsSublist.size(),
                                        iocType,
                                        shardFailure.toString()
                                );
                            }
                        }
                        listener.onResponse(new SearchHitsOrException(
                                searchResponse.getHits() == null || searchResponse.getHits().getHits() == null ?
                                emptyList() : Arrays.asList(searchResponse.getHits().getHits()), null));
                    },
                    e -> {
                        log.error(() -> new ParameterizedMessage("Threat intel monitor {} scan with {} user data indicators failed for ioc Type {}",
                                monitor.getId(),
                                iocsSublist.size(),
                                iocType), e
                        );
                        listener.onResponse(new SearchHitsOrException(emptyList(), e));
                    }
            ));
        }
    }

    private static SearchRequest getSearchRequestForIocType(List<String> indices, String iocType, List<String> iocsSublist) {
        SearchRequest searchRequest = new SearchRequest(indices.toArray(new String[0]));
        BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();
        // add the iocs sublist
        boolQueryBuilder.must(new TermsQueryBuilder(STIX2.VALUE_FIELD, iocsSublist));
        // add ioc type filter
        boolQueryBuilder.must(new TermsQueryBuilder(STIX2.TYPE_FIELD, iocType.toLowerCase()));
        searchRequest.source().query(boolQueryBuilder);
        return searchRequest;
    }

    /**
     * grouped listener for a given ioc type to listen and collate malicious iocs in search hits from batched search calls.
     * batching done for every 65536 or MAX_TERMS setting number of iocs in a list.
     */
    private GroupedActionListener<SearchHitsOrException> getGroupedListenerForIocScanPerIocType(Set<String> iocs, Monitor monitor, String iocType, GroupedActionListener<SearchHitsOrException> groupedListenerForAllIocTypes) {
        return new GroupedActionListener<>(
                ActionListener.wrap(
                        (Collection<SearchHitsOrException> searchHitsOrExceptions) -> {
                            if (false == searchHitsOrExceptions.stream().allMatch(shoe -> shoe.getException() != null)) {
                                List<SearchHit> searchHits = new ArrayList<>();
                                searchHitsOrExceptions.forEach(searchHitsOrException -> {
                                    if (searchHitsOrException.getException() != null) {
                                        log.error(
                                                () -> new ParameterizedMessage(
                                                        "Threat intel monitor {}: Failed to perform ioc scan on one batch for ioc type : ",
                                                        monitor.getId(), iocType), searchHitsOrException.getException());
                                    } else {
                                        searchHits.addAll(searchHitsOrException.getHits() != null ?
                                                searchHitsOrException.getHits() : emptyList());
                                    }
                                });
                                // we collect all hits we can and log all exceptions and submit to outer listener
                                groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(searchHits, null));
                            } else {
                                // we collect all exceptions under one exception and respond to outer listener
                                groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(emptyList(), buildException(searchHitsOrExceptions))
                                );
                            }
                        }, e -> {
                            log.error(
                                    () -> new ParameterizedMessage(
                                            "Threat intel monitor {}: Failed to perform ioc scan for ioc type : ",
                                            monitor.getId(), iocType), e);
                            groupedListenerForAllIocTypes.onResponse(new SearchHitsOrException(emptyList(), e));
                        }
                ),
                //TODO fix groupsize
                getGroupSizeForIocs(iocs) // batch into #MAX_TERMS setting
        );
    }

    private Exception buildException(Collection<SearchHitsOrException> searchHitsOrExceptions) {
        Exception e = null;
        for (SearchHitsOrException searchHitsOrException : searchHitsOrExceptions) {
            if (e == null)
                e = searchHitsOrException.getException();
            else {
                e.addSuppressed(searchHitsOrException.getException());
            }
        }
        return e;
    }

    private static int getGroupSizeForIocs(Set<String> iocs) {
        return iocs.size() / MAX_TERMS + (iocs.size() % MAX_TERMS == 0 ? 0 : 1);
    }

    @Override
    public List<String> getValuesAsStringList(SearchHit hit, String field) {
        if (hit.getFields().containsKey(field)) {
            DocumentField documentField = hit.getFields().get(field);
            return documentField.getValues().stream().filter(Objects::nonNull).map(Object::toString).collect(Collectors.toList());
        } else return emptyList();
    }

    @Override
    public String getIndexName(SearchHit hit) {
        return hit.getIndex();
    }

    @Override
    public String getId(SearchHit hit) {
        return hit.getId();
    }

    @Override
    void saveIocs(List<IocFinding> iocFindings, BiConsumer<List<IocFinding>, Exception> callback, Monitor monitor) {
        if (iocFindings == null || iocFindings.isEmpty()) {
            callback.accept(emptyList(), null);
            return;
        }
        log.debug("Threat intel monitor {}: Indexing {} ioc findings", monitor.getId(), iocFindings.size());
        iocFindingService.indexIocFindings(iocFindings, ActionListener.wrap(
                v -> {
                    callback.accept(iocFindings, null);
                },
                e -> {
                    log.error(
                            () -> new ParameterizedMessage(
                                    "Threat intel monitor {}: Failed to index ioc findings ",
                                    monitor.getId()), e
                    );
                    callback.accept(emptyList(), e);
                }
        ));
    }
}
