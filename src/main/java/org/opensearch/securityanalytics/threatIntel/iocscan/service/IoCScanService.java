package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.IocWithFeeds;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;
import org.opensearch.securityanalytics.threatIntel.model.monitor.PerIocTypeScanInput;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;


public abstract class IoCScanService<Data extends Object> implements IoCScanServiceInterface<Data> {
    private static final Logger log = LogManager.getLogger(IoCScanService.class);

    @Override
    public void scanIoCs(IocScanContext<Data> iocScanContext,
                         BiConsumer<Object, Exception> scanCallback
    ) {
        try {
            List<Data> data = iocScanContext.getData();
            if (data.isEmpty()) {
                scanCallback.accept(Collections.emptyList(), null);
                return;
            }
            Monitor monitor = iocScanContext.getMonitor();

            long startTime = System.currentTimeMillis();
            IocLookupDtos iocLookupDtos = extractIocsPerType(data, iocScanContext);
            BiConsumer<List<STIX2IOC>, Exception> iocScanResultConsumer = (List<STIX2IOC> maliciousIocs, Exception e) -> {
                long scanEndTime = System.currentTimeMillis();
                long timeTaken = scanEndTime - startTime;
                log.debug("Threat intel monitor {}: scan time taken is {}", monitor.getId(), timeTaken);
                if (e == null) {
                    createIocFindings(maliciousIocs, iocLookupDtos.iocValueToDocIdMap, iocScanContext,
                            (iocFindings, e1) -> {
                                if (e1 != null) {
                                    log.error(
                                            () -> new ParameterizedMessage("Threat intel monitor {}: Failed to create ioc findings/ ",
                                                    iocScanContext.getMonitor().getId(), data.size()),
                                            e1);
                                    scanCallback.accept(null, e1);
                                } else {
                                    BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer = (alerts, e2) -> {
                                        if (e2 != null) {
                                            log.error(
                                                    () -> new ParameterizedMessage("Threat intel monitor {}: Failed to execute threat intel triggers/ ",
                                                            iocScanContext.getMonitor().getId(), data.size()),
                                                    e2);
                                            scanCallback.accept(null, e2);
                                            return;
                                        } else {
                                            scanCallback.accept(data, null);
                                        }
                                    };
                                    executeTriggers(maliciousIocs, iocFindings, iocScanContext, data, iocLookupDtos,
                                            triggerResultConsumer);

                                }

                            }
                    );
                } else {
                    log.error(
                            () -> new ParameterizedMessage("Threat intel monitor {}: Failed to run scan for {} docs",
                                    iocScanContext.getMonitor().getId(), data.size()),
                            e);
                    scanCallback.accept(null, e);

                }
            };
            matchAgainstThreatIntelAndReturnMaliciousIocs(
                    iocLookupDtos.getIocsPerIocTypeMap(), monitor, iocScanResultConsumer, iocScanContext.getIocTypeToIndices());
        } catch (Exception e) {
            log.error(
                    () -> new ParameterizedMessage("Threat intel monitor {}: Unexpected failure in running scan for {} docs",
                            iocScanContext.getMonitor().getId(), iocScanContext.getData().size()),
                    e);
            scanCallback.accept(null, e);
        }
    }


    abstract void executeTriggers(List<STIX2IOC> maliciousIocs,
                                  List<IocFinding> iocFindings,
                                  IocScanContext<Data> iocScanContext,
                                  List<Data> data, IocLookupDtos iocLookupDtos,
                                  BiConsumer<List<ThreatIntelAlert>, Exception> triggerResultConsumer);

    abstract void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocsPerType,
            Monitor monitor,
            BiConsumer<List<STIX2IOC>, Exception> callback,
            Map<String, List<String>> iocTypeToIndices);

    /**
     * For each doc, we extract different maps for quick look up -
     * 1. map of iocs as key to ioc type
     * 2. ioc value to doc ids containing the ioc
     * 4. doc id to iocs map (reverse mapping of 2)
     */
    private IocLookupDtos extractIocsPerType
    (List<Data> data, IocScanContext<Data> context) {
        Map<String, Set<String>> iocsPerIocTypeMap = new HashMap<>();
        Map<String, Set<String>> iocValueToDocIdMap = new HashMap<>();
        Map<String, Set<String>> docIdToIocsMap = new HashMap<>();
        for (Data datum : data) {
            for (PerIocTypeScanInput iocTypeToIndexFieldMapping : context.getThreatIntelInput().getPerIocTypeScanInputList()) {
                String iocType = iocTypeToIndexFieldMapping.getIocType().toLowerCase();
                String concreteIndex = getIndexName(datum);
                if (context.getConcreteIndexToMonitorInputIndicesMap().containsKey(concreteIndex)
                        && false == context.getConcreteIndexToMonitorInputIndicesMap().get(concreteIndex).isEmpty()
                ) {
                    // if concrete index resolves to multiple monitor input indices, it's undesirable. We just pick any one of the monitor input indices to get fields for each ioc.
                    String index = context.getConcreteIndexToMonitorInputIndicesMap().get(concreteIndex).get(0);
                    List<String> fields = iocTypeToIndexFieldMapping.getIndexToFieldsMap().get(index);
                    for (String field : fields) {
                        List<String> vals = getValuesAsStringList(datum, field);
                        String id = getId(datum);
                        String docId = id + ":" + index;
                        Set<String> iocs = docIdToIocsMap.getOrDefault(docIdToIocsMap.get(docId), new HashSet<>());
                        iocs.addAll(vals);
                        docIdToIocsMap.put(docId, iocs);
                        for (String ioc : vals) {
                            Set<String> docIds = iocValueToDocIdMap.getOrDefault(iocValueToDocIdMap.get(ioc), new HashSet<>());
                            docIds.add(docId);
                            iocValueToDocIdMap.put(ioc, docIds);
                        }
                        if (false == vals.isEmpty()) {
                            iocs = iocsPerIocTypeMap.getOrDefault(iocType, new HashSet<>());
                            iocs.addAll(vals);
                            iocsPerIocTypeMap.put(iocType, iocs);
                        }
                    }
                }
            }
        }
        return new IocLookupDtos(iocsPerIocTypeMap, iocValueToDocIdMap, docIdToIocsMap);
    }

    abstract List<String> getValuesAsStringList(Data datum, String field);

    abstract String getIndexName(Data datum);

    abstract String getId(Data datum);

    private void createIocFindings(List<STIX2IOC> iocs,
                                   Map<String, Set<String>> iocValueToDocIdMap,
                                   IocScanContext iocScanContext,
                                   BiConsumer<List<IocFinding>, Exception> callback) {
        try {
            Instant timestamp = Instant.now();
            Monitor monitor = iocScanContext.getMonitor();
            // Map to collect unique IocValue with their respective FeedIds
            Map<String, Set<IocWithFeeds>> iocValueToFeedIds = new HashMap<>();
            Map<String, String> iocValueToType = new HashMap<>();
            for (STIX2IOC ioc : iocs) {
                String iocValue = ioc.getValue();
                if (false == iocValueToType.containsKey(iocValue))
                    iocValueToType.put(iocValue, ioc.getType().toString());
                iocValueToFeedIds
                        .computeIfAbsent(iocValue, k -> new HashSet<>())
                        .add(new IocWithFeeds(ioc.getId(), ioc.getFeedId(), ioc.getFeedName(), "")); //todo figure how to store index
            }

            List<IocFinding> iocFindings = new ArrayList<>();

            for (Map.Entry<String, Set<IocWithFeeds>> entry : iocValueToFeedIds.entrySet()) {
                String iocValue = entry.getKey();
                Set<IocWithFeeds> iocWithFeeds = entry.getValue();

                List<String> relatedDocIds = new ArrayList<>(iocValueToDocIdMap.getOrDefault(iocValue, new HashSet<>()));
                List<IocWithFeeds> feedIdsList = new ArrayList<>(iocWithFeeds);
                try {
                    IocFinding iocFinding = new IocFinding(
                            UUID.randomUUID().toString(), // Generating a unique ID
                            relatedDocIds,
                            feedIdsList, // update to object
                            monitor.getId(),
                            monitor.getName(),
                            iocValue,
                            iocValueToType.get(iocValue),
                            timestamp,
                            UUID.randomUUID().toString() // TODO execution ID
                    );
                    iocFindings.add(iocFinding);
                } catch (Exception e) {
                    log.error(String.format("skipping creating ioc finding for %s due to unexpected failure.", entry.getKey()), e);
                }
            }
            saveIocFindings(iocFindings, callback, monitor);
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Failed to create ioc findinges due to unexpected error {}", iocScanContext.getMonitor().getId()), e);
            callback.accept(null, e);
        }
    }

    abstract void saveIocFindings
            (List<IocFinding> iocs, BiConsumer<List<IocFinding>, Exception> callback, Monitor monitor);

    abstract void saveAlerts(List<ThreatIntelAlert> updatedAlerts, List<ThreatIntelAlert> newAlerts, Monitor monitor, BiConsumer<List<ThreatIntelAlert>, Exception> callback);

    protected static class IocLookupDtos {
        private final Map<String, Set<String>> iocsPerIocTypeMap;
        private final Map<String, Set<String>> iocValueToDocIdMap;
        private final Map<String, Set<String>> docIdToIocsMap;

        public IocLookupDtos(Map<String, Set<String>> iocsPerIocTypeMap, Map<String, Set<String>> iocValueToDocIdMap, Map<String, Set<String>> docIdToIocsMap) {
            this.iocsPerIocTypeMap = iocsPerIocTypeMap;
            this.iocValueToDocIdMap = iocValueToDocIdMap;
            this.docIdToIocsMap = docIdToIocsMap;
        }

        public Map<String, Set<String>> getIocsPerIocTypeMap() {
            return iocsPerIocTypeMap;
        }

        public Map<String, Set<String>> getIocValueToDocIdMap() {
            return iocValueToDocIdMap;
        }

        public Map<String, Set<String>> getDocIdToIocsMap() {
            return docIdToIocsMap;
        }
    }

}
