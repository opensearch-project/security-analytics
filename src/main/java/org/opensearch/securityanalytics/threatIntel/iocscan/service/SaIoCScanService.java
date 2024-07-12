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
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorTrigger;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelTrigger;
import org.opensearch.securityanalytics.threatIntel.model.monitor.TransportThreatIntelMonitorFanOutAction.SearchHitsOrException;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils.getThreatIntelTriggerFromBytesReference;

public class SaIoCScanService extends IoCScanService<SearchHit> {

    private static final Logger log = LogManager.getLogger(SaIoCScanService.class);
    public static final int MAX_TERMS = 65536; //TODO make ioc index setting based. use same setting value to create index
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final IocFindingService iocFindingService;
    private final ThreatIntelAlertService threatIntelAlertService;
    private final NotificationService notificationService;

    public SaIoCScanService(Client client, NamedXContentRegistry xContentRegistry, IocFindingService iocFindingService,
                            ThreatIntelAlertService threatIntelAlertService, NotificationService notificationService) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.iocFindingService = iocFindingService;
        this.threatIntelAlertService = threatIntelAlertService;
        this.notificationService = notificationService;
    }

    @Override
    void executeTriggers(List<STIX2IOC> maliciousIocs, List<IocFinding> iocFindings, IocScanContext<SearchHit> iocScanContext, List<SearchHit> searchHits, IoCScanService.IocLookupDtos iocLookupDtos, BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer) {
        Monitor monitor = iocScanContext.getMonitor();
        if (maliciousIocs.isEmpty() || monitor.getTriggers().isEmpty()) {
            triggerResultConsumer.accept(Collections.emptyList(), null);
            return;
        }
        initAlertsIndex(
                ActionListener.wrap(
                        r -> {
                            GroupedActionListener<List<ThreatIntelAlert>> allTriggerResultListener = getGroupedListenerForAllTriggersResponse(iocScanContext.getMonitor(),
                                    triggerResultConsumer);
                            for (Trigger trigger : monitor.getTriggers()) {
                                executeTrigger(iocFindings, trigger, monitor, allTriggerResultListener);
                            }
                        },
                        e -> {
                            log.error(() -> new ParameterizedMessage(
                                    "Threat intel monitor {} Failed to execute triggers . Failed to initialize threat intel alerts index",
                                    monitor.getId()), e);
                            triggerResultConsumer.accept(Collections.emptyList(), null);
                        }
                )
        );
    }

    private void executeTrigger(List<IocFinding> iocFindings,
                                Trigger trigger,
                                Monitor monitor,
                                ActionListener<List<ThreatIntelAlert>> listener) {
        try {
            RemoteMonitorTrigger remoteMonitorTrigger = (RemoteMonitorTrigger) trigger;
            ThreatIntelTrigger threatIntelTrigger = getThreatIntelTriggerFromBytesReference(remoteMonitorTrigger, xContentRegistry);
            ArrayList<IocFinding> triggerMatchedFindings = ThreatIntelMonitorUtils.getTriggerMatchedFindings(iocFindings, threatIntelTrigger);
            if (triggerMatchedFindings.isEmpty()) {
                log.debug("Threat intel monitor {} no matches for trigger {}", monitor.getId(), trigger.getName());
                listener.onResponse(emptyList());
            } else {
                fetchExistingAlertsForTrigger(monitor, triggerMatchedFindings, trigger, ActionListener.wrap(
                        existingAlerts -> {
                            executeActionsAndSaveAlerts(iocFindings, trigger, monitor, existingAlerts, triggerMatchedFindings, threatIntelTrigger, listener);
                        },
                        e -> {
                            log.error(() -> new ParameterizedMessage(
                                    "Threat intel monitor {} Failed to execute trigger {}. Failure while fetching existing alerts",
                                    monitor.getId(), trigger.getName()), e);
                            listener.onFailure(e);
                        }
                ));
            }
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage(
                            "Threat intel monitor {} Failed to execute trigger {}", monitor.getId(), trigger.getName()),
                    e
            );
            listener.onFailure(e);
        }
    }

    private void executeActionsAndSaveAlerts(List<IocFinding> iocFindings,
                                             Trigger trigger,
                                             Monitor monitor,
                                             List<ThreatIntelAlert> existingAlerts,
                                             ArrayList<IocFinding> triggerMatchedFindings,
                                             ThreatIntelTrigger threatIntelTrigger, ActionListener<List<ThreatIntelAlert>> listener) {
        Map<String, ThreatIntelAlert> iocToUpdatedAlertsMap = ThreatIntelMonitorUtils.prepareAlertsToUpdate(triggerMatchedFindings, existingAlerts);
        List<ThreatIntelAlert> newAlerts = ThreatIntelMonitorUtils.prepareNewAlerts(monitor, trigger, triggerMatchedFindings, iocToUpdatedAlertsMap);
        ThreatIntelAlertContext ctx = new ThreatIntelAlertContext(threatIntelTrigger,
                trigger,
                iocFindings,
                monitor,
                newAlerts,
                existingAlerts);
        if (false == trigger.getActions().isEmpty()) {
            GroupedActionListener<Void> notifsListener = new GroupedActionListener<>(ActionListener.wrap(
                    r -> {
                        saveAlerts(new ArrayList<>(iocToUpdatedAlertsMap.values()),
                                newAlerts,
                                monitor,
                                (threatIntelAlerts, e) -> {
                                    if (e != null) {
                                        log.error(String.format("Threat intel monitor %s: Failed to save alerts for trigger {}", monitor.getId(), trigger.getId()), e);
                                        listener.onFailure(e);
                                    } else {
                                        listener.onResponse(threatIntelAlerts);
                                    }
                                });
                    }, e -> {
                        log.error(String.format("Threat intel monitor %s: Failed to send notification for trigger {}", monitor.getId(), trigger.getId()), e);
                        listener.onFailure(new SecurityAnalyticsException("Failed to send notification", RestStatus.INTERNAL_SERVER_ERROR, e));
                    }
            ), trigger.getActions().size());
            for (Action action : trigger.getActions()) {
                try {
                    String transformedSubject = NotificationService.compileTemplate(ctx, action.getSubjectTemplate());
                    String transformedMessage = NotificationService.compileTemplate(ctx, action.getMessageTemplate());
                    String configId = action.getDestinationId();
                    notificationService.sendNotification(configId, trigger.getSeverity(), transformedSubject, transformedMessage, notifsListener);
                } catch (Exception e) {
                    log.error(String.format("Threat intel monitor %s: Failed to send notification to %s for trigger %s", monitor.getId(), action.getDestinationId(), trigger.getId()), e);
                    notifsListener.onFailure(new SecurityAnalyticsException("Failed to send notification", RestStatus.INTERNAL_SERVER_ERROR, e));
                }

            }
        } else {
            saveAlerts(new ArrayList<>(iocToUpdatedAlertsMap.values()),
                    newAlerts,
                    monitor,
                    (threatIntelAlerts, e) -> {
                        if (e != null) {
                            log.error(String.format("Threat intel monitor %s: Failed to save alerts for trigger %s", monitor.getId(), trigger.getId()), e);
                            listener.onFailure(e);
                        } else {
                            listener.onResponse(threatIntelAlerts);
                        }
                    });
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
        threatIntelAlertService.search(ssb, ActionListener.wrap(
                searchResponse -> {
                    List<ThreatIntelAlert> alerts = new ArrayList<>();
                    if (searchResponse.getHits() == null || searchResponse.getHits().getHits() == null) {
                        listener.onResponse(alerts);
                        return;
                    }
                    for (SearchHit hit : searchResponse.getHits().getHits()) {
                        XContentParser xcp = XContentType.JSON.xContent().createParser(
                                xContentRegistry,
                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                        );
                        if(xcp.currentToken() == null)
                            xcp.nextToken();
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

    private GroupedActionListener<List<ThreatIntelAlert>> getGroupedListenerForAllTriggersResponse(Monitor monitor, BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer) {
        return new GroupedActionListener<>(ActionListener.wrap(
                r -> {
                    List<ThreatIntelAlert> list = new ArrayList<>();
                    r.forEach(list::addAll);
                    triggerResultConsumer.accept(list, null); //todo change emptylist to actual response
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
        boolQueryBuilder.must(new TermsQueryBuilder(STIX2.VALUE_FIELD + ".keyword", iocsSublist));
        // add ioc type filter
        boolQueryBuilder.must(new TermsQueryBuilder(STIX2.TYPE_FIELD + ".keyword", iocType.toLowerCase(Locale.ROOT)));
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

    private void initAlertsIndex(ActionListener<Void> listener) {
        threatIntelAlertService.createIndexIfNotExists(listener);
    }
}
