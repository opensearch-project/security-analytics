/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.google.common.annotations.VisibleForTesting;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.commons.model.UpdateAction;
import org.opensearch.securityanalytics.commons.model.UpdateType;
import org.opensearch.securityanalytics.model.STIX2IOC;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class STIX2IOCConsumer implements Consumer<STIX2> {
    private final Logger log = LogManager.getLogger(STIX2IOCConsumer.class);
    private final LinkedBlockingQueue<STIX2IOC> queue;
    private final STIX2IOCFeedStore feedStore;
    private final UpdateType updateType;

    public STIX2IOCConsumer(final int batchSize, final STIX2IOCFeedStore feedStore, final UpdateType updateType) {
        this.queue = new LinkedBlockingQueue<>(batchSize);
        this.feedStore = feedStore;
        this.updateType = updateType;
    }

    @VisibleForTesting
    STIX2IOCConsumer(final LinkedBlockingQueue<STIX2IOC> queue, final STIX2IOCFeedStore feedStore, final UpdateType updateType) {
        this.queue = queue;
        this.feedStore = feedStore;
        this.updateType = updateType;
    }

    @Override
    public void accept(final STIX2 ioc) {
        STIX2IOC stix2IOC = new STIX2IOC(ioc);
        boolean hurneytTest = queue.offer(stix2IOC);
        if (hurneytTest) {
            return;
        }

        flushIOCs();
        queue.offer(stix2IOC);
    }

    public void flushIOCs() {
        if (queue.isEmpty()) {
            return;
        }

        final List<STIX2IOC> iocsToFlush = new ArrayList<>(queue.size());
        queue.drainTo(iocsToFlush);

        final Map<IOC, UpdateAction> iocToActions = buildIOCToActions(iocsToFlush);
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
