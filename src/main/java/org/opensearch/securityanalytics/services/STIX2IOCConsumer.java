/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.commons.model.UpdateAction;
import org.opensearch.securityanalytics.commons.model.UpdateType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class STIX2IOCConsumer implements Consumer<STIX2> {
    private final Logger log = LogManager.getLogger(STIX2IOCConsumer.class);
    private final LinkedBlockingQueue<STIX2IOC> queue;
    private final STIX2IOCFeedStore feedStore;
    private final UpdateType updateType;
    private final SATIFSourceConfig saTifSourceConfig;
    private final Set<String> iocTypes;

    public STIX2IOCConsumer(final int batchSize, final STIX2IOCFeedStore feedStore, final UpdateType updateType, SATIFSourceConfig saTifSourceConfig) {
        this.queue = new LinkedBlockingQueue<>(batchSize);
        this.feedStore = feedStore;
        this.updateType = updateType;
        this.saTifSourceConfig = saTifSourceConfig;
        this.iocTypes = new HashSet<>();
    }

    @Override
    public void accept(final STIX2 ioc) {
        STIX2IOC stix2IOC = new STIX2IOC(
                ioc,
                feedStore.getSaTifSourceConfig().getId(),
                feedStore.getSaTifSourceConfig().getName()
        );
        iocTypes.add(ioc.getType());
        if (queue.offer(stix2IOC)) {
            return;
        }

        flushIOCs();
        queue.offer(stix2IOC);
    }

    public void flushIOCs() {
        if (queue.isEmpty()) {
            throw new OpenSearchStatusException("No compatible Iocs were downloaded for config " + feedStore.getSaTifSourceConfig().getName(), RestStatus.BAD_REQUEST);
        }

        final List<STIX2IOC> iocsToFlush = new ArrayList<>(queue.size());
        queue.drainTo(iocsToFlush);

        final Map<IOC, UpdateAction> iocToActions = buildIOCToActions(iocsToFlush);
        saTifSourceConfig.setIocTypes(new ArrayList<>(iocTypes));
        feedStore.storeIOCs(iocToActions);
    }

    private Map<IOC, UpdateAction> buildIOCToActions(final List<STIX2IOC> iocs) {
        switch (updateType) {
            case REPLACE: return buildReplaceActions(iocs);
            case DELTA: return buildDeltaActions(iocs);
            default: throw new IllegalArgumentException("Invalid update type: " + updateType);
        }
    }

    private Map<IOC, UpdateAction> buildReplaceActions(final List<STIX2IOC> iocs) {
        return iocs.stream()
                .map(ioc -> Map.entry(ioc, UpdateAction.UPSERT))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private Map<IOC, UpdateAction> buildDeltaActions(final List<STIX2IOC> iocs) {
        throw new UnsupportedOperationException("Delta update type is not yet supported");
    }
}
