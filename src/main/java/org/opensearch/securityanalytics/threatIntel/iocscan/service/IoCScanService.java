package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;
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

        List<Data> data = iocScanContext.getData();
        if (data.isEmpty() == false) {
            scanCallback.accept(Collections.emptyList(), null);
            return;
        }
        Monitor monitor = iocScanContext.getMonitor();

        long start = System.currentTimeMillis();
        // log.debug("beginning to scan IoC's")
        IocLookupDtos iocLookupDtos = extractIocPerTypeSet(data, iocScanContext.getThreatIntelInput().getPerIocTypeScanInputList());
        BiConsumer<List<STIX2IOC>, Exception> iocScanResultConsumer = (List<STIX2IOC> maliciousIocs, Exception e) -> {
            if (e == null) {
                createIoCMatches(maliciousIocs, iocLookupDtos.iocValueToDocIdMap, iocScanContext,
                        new BiConsumer<List<STIX2IOC>, Exception>() {
                            @Override
                            public void accept(List<STIX2IOC> iocs, Exception e) {
                                // TODO create alerts
                            }
                        }
                );

            } else {
                //                onIocMatchFailure(e, iocScanMonitor);

            }
        };
        matchAgainstThreatIntelAndReturnMaliciousIocs(
                iocLookupDtos.getIocsPerIocTypeMap(), monitor, iocScanResultConsumer, iocScanContext.getIocTypeToIndices());
    }

    abstract void matchAgainstThreatIntelAndReturnMaliciousIocs(
            Map<String, Set<String>> iocPerTypeSet,
            Monitor iocScanMonitor,
            BiConsumer<List<STIX2IOC>, Exception> callback, Map<String, List<String>> iocTypeToIndices);

    /**
     * For each doc, we extract the list of
     */
    private IocLookupDtos extractIocPerTypeSet(List<Data> data, List<PerIocTypeScanInput> iocTypeToIndexFieldMappings) {
        Map<String, Set<String>> iocsPerIocTypeMap = new HashMap<>();
        Map<String, Set<String>> iocValueToDocIdMap = new HashMap<>();
        Map<String, Set<String>> docIdToIocsMap = new HashMap<>();
        for (Data datum : data) {
            for (PerIocTypeScanInput iocTypeToIndexFieldMapping : iocTypeToIndexFieldMappings) {
                String iocType = iocTypeToIndexFieldMapping.getIocType();
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

    private void createIoCMatches(List<STIX2IOC> iocs,
                                  Map<String, Set<String>> iocValueToDocIdMap,
                                  IocScanContext iocScanContext,
                                  BiConsumer<List<STIX2IOC>, Exception> callback) {
        try {
            Instant timestamp = Instant.now();
            Monitor monitor = iocScanContext.getMonitor();
            // Map to collect unique IocValue with their respective FeedIds
            Map<String, Set<String>> iocValueToFeedIds = new HashMap<>();
            Map<String, String> iocValueToType = new HashMap<>();
            for (STIX2IOC ioc : iocs) {
                String iocValue = ioc.getValue();
                if(false == iocValueToType.containsKey(iocValueToType))
                    iocValueToType.put(iocValue, ioc.getType().toString());
                iocValueToFeedIds
                        .computeIfAbsent(iocValue, k -> new HashSet<>())
                        .add(ioc.getFeedId());
            }

            List<IocMatch> iocMatches = new ArrayList<>();

            for (Map.Entry<String, Set<String>> entry : iocValueToFeedIds.entrySet()) {
                String iocValue = entry.getKey();
                Set<String> feedIds = entry.getValue();

                List<String> relatedDocIds = new ArrayList<>(iocValueToDocIdMap.getOrDefault(iocValue, new HashSet<>()));
                List<String> feedIdsList = new ArrayList<>(feedIds);
                try {
                    IocMatch iocMatch = new IocMatch(
                            UUID.randomUUID().toString(), // Generating a unique ID
                            relatedDocIds,
                            feedIdsList,
                            monitor.getId(),
                            monitor.getName(),
                            iocValue,
                            iocValueToType.get(iocValue),
                            timestamp,
                            UUID.randomUUID().toString() // TODO execution ID
                    );
                    iocMatches.add(iocMatch);
                } catch (Exception e) {
                    log.error(String.format("skipping creating ioc match for %s due to unexpected failure.", entry.getKey()), e);
                }
            }
            saveIocs(iocs, callback);
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Failed to create ioc matches due to unexpected error {}", iocScanContext.getMonitor().getId()), e);
            callback.accept(null, e);
        }
    }

    abstract void saveIocs(List<STIX2IOC> iocs, BiConsumer<List<STIX2IOC>, Exception> callback);

    private static class IocMatchDto {
        private final String iocValue;
        private final String iocType;
        private final List<STIX2IOC> iocs;
        private final List<String> docIdsContainingIoc;

        public IocMatchDto(String iocValue, String iocType, List<STIX2IOC> iocs, List<String> docIdsContainingIoc) {
            this.iocValue = iocValue;
            this.iocType = iocType;
            this.iocs = iocs;
            this.docIdsContainingIoc = docIdsContainingIoc;
        }

        public String getIocValue() {
            return iocValue;
        }

        public String getIocType() {
            return iocType;
        }

        public List<STIX2IOC> getIocs() {
            return iocs;
        }

        public List<String> getDocIdsContainingIoc() {
            return docIdsContainingIoc;
        }
    }

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
