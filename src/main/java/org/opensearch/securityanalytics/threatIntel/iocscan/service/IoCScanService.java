package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
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
            // log.debug("beginning to scan IoC's")
            IocLookupDtos iocLookupDtos = extractIocPerTypeSet(data, iocScanContext.getThreatIntelInput().getPerIocTypeScanInputList());
            BiConsumer<List<STIX2IOC>, Exception> iocScanResultConsumer = (List<STIX2IOC> maliciousIocs, Exception e) -> {
                long scanEndTime = System.currentTimeMillis();
                long timeTaken = scanEndTime - startTime;
                log.debug("Threat intel monitor {}: scan time taken is {}", monitor.getId(), timeTaken);
                if (e == null) {
                    createIocFindings(maliciousIocs, iocLookupDtos.iocValueToDocIdMap, iocScanContext,
                            new BiConsumer<List<IocFinding>, Exception>() {
                                @Override
                                public void accept(List<IocFinding> iocFindings, Exception e) {
                                    // TODO create alerts and move scan callback inside create alerts, notifs response

                                    scanCallback.accept(iocFindings, e);
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

    abstract void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocsPerType,
            Monitor monitor,
            BiConsumer<List<STIX2IOC>, Exception> callback,
            Map<String, List<String>> iocTypeToIndices);

    /**
     * For each doc, we extract the list of
     */
    private IocLookupDtos extractIocPerTypeSet(List<Data> data, List<PerIocTypeScanInput> iocTypeToIndexFieldMappings) {
        Map<String, Set<String>> iocsPerIocTypeMap = new HashMap<>();
        Map<String, Set<String>> iocValueToDocIdMap = new HashMap<>();
        Map<String, Set<String>> docIdToIocsMap = new HashMap<>();
        for (Data datum : data) {
            for (PerIocTypeScanInput iocTypeToIndexFieldMapping : iocTypeToIndexFieldMappings) {
                String iocType = iocTypeToIndexFieldMapping.getIocType().toLowerCase();
                String index = getIndexName(datum);
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
            Map<String, Set<String>> iocValueToFeedIds = new HashMap<>();
            Map<String, String> iocValueToType = new HashMap<>();
            for (STIX2IOC ioc : iocs) {
                String iocValue = ioc.getValue();
                if (false == iocValueToType.containsKey(iocValueToType))
                    iocValueToType.put(iocValue, ioc.getType().toString());
                iocValueToFeedIds
                        .computeIfAbsent(iocValue, k -> new HashSet<>())
                        .add(ioc.getFeedId());
            }

            List<IocFinding> iocFindings = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : iocValueToFeedIds.entrySet()) {
                String iocValue = entry.getKey();
                Set<String> feedIds = entry.getValue();

                List<String> relatedDocIds = new ArrayList<>(iocValueToDocIdMap.getOrDefault(iocValue, new HashSet<>()));
                List<String> feedIdsList = new ArrayList<>(feedIds);
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
            saveIocs(iocFindings, callback, monitor);
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Failed to create ioc findinges due to unexpected error {}", iocScanContext.getMonitor().getId()), e);
            callback.accept(null, e);
        }
    }

    abstract void saveIocs(List<IocFinding> iocs, BiConsumer<List<IocFinding>, Exception> callback, Monitor monitor);

    private static class IocLookupDtos {
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
