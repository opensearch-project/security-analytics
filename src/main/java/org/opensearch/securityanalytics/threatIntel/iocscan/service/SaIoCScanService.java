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
import org.opensearch.commons.alerting.model.Trigger;
import org.opensearch.commons.alerting.model.TriggerRunResult;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorTrigger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelTriggerRunResult;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelTrigger;
import org.opensearch.securityanalytics.threatIntel.model.monitor.TransportThreatIntelMonitorFanOutAction.SearchHitsOrException;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils.getThreatIntelTriggerFromBytesReference;

public class SaIoCScanService extends IoCScanService<SearchHit> {

    private static final Logger log = LogManager.getLogger(SaIoCScanService.class);
    public static final int MAX_TERMS = 65536; //TODO make ioc index setting based. use same setting value to create index
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final IocFindingService iocFindingService;
    private final ThreatIntelAlertService threatIntelAlertService;

    public SaIoCScanService(Client client, NamedXContentRegistry xContentRegistry, IocFindingService iocFindingService,
                            ThreatIntelAlertService threatIntelAlertService) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.iocFindingService = iocFindingService;
        this.threatIntelAlertService = threatIntelAlertService;
    }

    @Override
    void executeTriggers(List<STIX2IOC> maliciousIocs, List<IocFinding> iocFindings, IocScanContext<SearchHit> iocScanContext, List<SearchHit> searchHits, IoCScanService.IocLookupDtos iocLookupDtos, BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer) {
        Monitor monitor = iocScanContext.getMonitor();
        if (maliciousIocs.isEmpty() || monitor.getTriggers().isEmpty()) {
            triggerResultConsumer.accept(Collections.emptyList(), null); //todo emptyTriggerRunList
            return;
        }
        GroupedActionListener<TriggerRunResult> allTriggerResultListener = getGroupedListenerForAllTriggersResponse(iocScanContext.getMonitor(),
                triggerResultConsumer);
        for (Trigger trigger : monitor.getTriggers()) {
            executeTrigger(iocFindings, trigger, monitor, allTriggerResultListener);
        }
    }

    private void executeTrigger(List<IocFinding> iocFindings, Trigger trigger, Monitor monitor, ActionListener<TriggerRunResult> listener) {
        try {

            RemoteMonitorTrigger remoteMonitorTrigger = (RemoteMonitorTrigger) trigger;
            ThreatIntelTrigger threatIntelTrigger = getThreatIntelTriggerFromBytesReference(remoteMonitorTrigger, xContentRegistry);
            ArrayList<IocFinding> triggerMatchedFindings = new ArrayList();
            for (IocFinding iocFinding : iocFindings) {
                boolean iocTypeConditionMatch = false;
                if (threatIntelTrigger.getIocTypes() == null || threatIntelTrigger.getIocTypes().isEmpty()) {
                    iocTypeConditionMatch = true;
                } else if (threatIntelTrigger.getIocTypes().contains(iocFinding.getIocType().toLowerCase())) {
                    iocTypeConditionMatch = true;
                }
                boolean dataSourcesConditionMatch = false;
                if (threatIntelTrigger.getDataSources() == null || threatIntelTrigger.getDataSources().isEmpty()) {
                    dataSourcesConditionMatch = true;
                } else {
                    List<String> dataSources = iocFinding.getRelatedDocIds().stream().map(it -> {
                        String[] parts = it.split(":");
                        if (parts.length == 2) {
                            return parts[1];
                        } else return null;
                    }).filter(Objects::nonNull).collect(Collectors.toList());
                    if (threatIntelTrigger.getDataSources().stream().anyMatch(dataSources::contains)) {
                        dataSourcesConditionMatch = true;
                    }
                }
                if (dataSourcesConditionMatch && iocTypeConditionMatch) {
                    triggerMatchedFindings.add(iocFinding);
                }
            }
            if (triggerMatchedFindings.isEmpty()) {
                log.debug("Threat intel monitor {} no matches for trigger {}", monitor.getId(), trigger.getName());
                listener.onResponse(new ThreatIntelTriggerRunResult(
                        trigger.getName(),
                        emptyList(),
                        null,
                        emptyMap()
                ));
            } else {
                fetchExistingAlertsForTrigger(monitor, triggerMatchedFindings, trigger, ActionListener.wrap(
                        existingAlerts -> {
                            Map<String, ThreatIntelAlert> iocToUpdatedAlertsMap = ThreatIntelMonitorUtils.prepareAlertsToUpdate(triggerMatchedFindings, existingAlerts);
                            List<ThreatIntelAlert> newAlerts = ThreatIntelMonitorUtils.prepareNewAlerts(monitor, trigger, triggerMatchedFindings, iocToUpdatedAlertsMap);
                            ThreatIntelAlertContext threatIntelAlertContext = new ThreatIntelAlertContext(threatIntelTrigger,
                                    trigger,
                                    iocFindings,
                                    monitor,
                                    newAlerts,
                                    existingAlerts);
                            for (Action action : trigger.getActions()) {
                                String configId = action.getDestinationId();
//                                String transformedSubject = notificationService.compileTemplate(ctx, action.getSubjectTemplate());

                            }

                            saveAlerts(new ArrayList<>(iocToUpdatedAlertsMap.values()),
                                    newAlerts,
                                    monitor,
                                    new BiConsumer<List<ThreatIntelAlert>, Exception>() {
                                        @Override
                                        public void accept(List<ThreatIntelAlert> threatIntelAlerts, Exception e) {

                                        }
                                    });


                        },
                        e -> {
                            log.error(() -> new ParameterizedMessage(
                                            "Threat intel monitor {} Failed to execute trigger {}. Failure while fetching existing alerts",
                                            monitor.getId(), trigger.getName()),
                                    e
                            );
                            listener.onResponse(new ThreatIntelTriggerRunResult(
                                    trigger.getName(),
                                    emptyList(),//todo
                                    e,
                                    Collections.emptyMap()
                            ));
                        }
                ));
            }
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage(
                            "Threat intel monitor {} Failed to execute trigger {}", monitor.getId(), trigger.getName()),
                    e
            );
            listener.onResponse(new ThreatIntelTriggerRunResult(
                    trigger.getName(),
                    emptyList(),//todo
                    e,
                    Collections.emptyMap()
            ));
        }
    }

    private void fetchExistingAlertsForTrigger(Monitor monitor,
                                               ArrayList<IocFinding> findings,
                                               Trigger trigger,
                                               ActionListener<List<ThreatIntelAlert>> listener) {
        if (findings.isEmpty()) {
            listener.onResponse(emptyList());
            return;
        }
        SearchSourceBuilder ssb = ThreatIntelMonitorUtils.getSearchSourceBuilderForExistingAlertsQuery(findings, trigger);
        threatIntelAlertService.searchEntities(ssb, ActionListener.wrap(
                searchResponse -> {
                    List<ThreatIntelAlert> alerts = new ArrayList<>();
                    if (searchResponse.getHits() == null || searchResponse.getHits().getHits() == null) {
                        listener.onResponse(alerts);
                        return;
                    }
                    for (SearchHit hit : searchResponse.getHits().getHits()) {
                        XContentParser xcp = XContentType.JSON.xContent().createParser(
                                xContentRegistry,
                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
                        ThreatIntelAlert alert = ThreatIntelAlert.parse(xcp, hit.getVersion());
                        alerts.add(alert);
                    }
                    listener.onResponse(alerts);
                },
                e -> {
                    log.error(() -> new ParameterizedMessage(
                                    "Threat intel monitor {} Failed to execute trigger {}. Unexpected error in fetching existing alerts for dedupe", monitor.getId(), trigger.getName()),
                            e
                    );
                    listener.onFailure(e);
                }
        ));
    }

    private GroupedActionListener<TriggerRunResult> getGroupedListenerForAllTriggersResponse(Monitor monitor, BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer) {
        return new GroupedActionListener<>(ActionListener.wrap(
                r -> {
                    triggerResultConsumer.accept(emptyList(), null); //todo change emptylist to actual response
                }, e -> {
                    log.error(() -> new ParameterizedMessage(
                                    "Threat intel monitor {} Failed to execute triggers {}", monitor.getId()),
                            e
                    );
                    triggerResultConsumer.accept(emptyList(), e);
                }
        ), monitor.getTriggers().size());
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
    void saveIocFindings(List<IocFinding> iocFindings, BiConsumer<List<IocFinding>, Exception> callback, Monitor monitor) {
        if (iocFindings == null || iocFindings.isEmpty()) {
            callback.accept(emptyList(), null);
            return;
        }
        log.debug("Threat intel monitor {}: Indexing {} ioc findings", monitor.getId(), iocFindings.size());
        iocFindingService.bulkIndexEntities(iocFindings, ActionListener.wrap(
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

    @Override
    void saveAlerts(List<ThreatIntelAlert> updatedAlerts, List<ThreatIntelAlert> newAlerts, Monitor monitor, BiConsumer<List<ThreatIntelAlert>, Exception> callback) {
        if ((newAlerts == null || newAlerts.isEmpty()) && (updatedAlerts == null || updatedAlerts.isEmpty())) {
            callback.accept(emptyList(), null);
            return;
        }
        log.debug("Threat intel monitor {}: Indexing {} new threat intel alerts and updating {} existing alerts", monitor.getId(), newAlerts.size(), updatedAlerts.size());
        threatIntelAlertService.bulkIndexEntities(newAlerts, updatedAlerts, ActionListener.wrap(
                v -> {
                    ArrayList<ThreatIntelAlert> threatIntelAlerts = new ArrayList<>(newAlerts);
                    threatIntelAlerts.addAll(updatedAlerts);
                    callback.accept(threatIntelAlerts, null);
                },
                e -> {
                    log.error(
                            () -> new ParameterizedMessage(
                                    "Threat intel monitor {}: Failed to index alerts ",
                                    monitor.getId()), e
                    );
                    callback.accept(emptyList(), e);
                }
        ));
    }
}
