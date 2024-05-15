/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.feed.retriever;

import org.opensearch.securityanalytics.connector.IOCConnector;
import org.opensearch.securityanalytics.feed.store.FeedStore;
import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.model.IOC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class FeedRetriever implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(FeedRetriever.class);

    private final IOCConnector iocConnector;
    private final FeedStore feedStore;
    private final UpdateType updateType;
    private final String feedId;

    public FeedRetriever(final IOCConnector iocConnector, final FeedStore feedStore, final UpdateType updateType, final String feedId) {
        this.iocConnector = iocConnector;
        this.feedStore = feedStore;
        this.updateType = updateType;
        this.feedId = feedId;
    }

    @Override
    public void run() {
        try {
            final List<IOC> iocs = iocConnector.loadIOCs();
            feedStore.storeIOCs(iocs, updateType);
        } catch (final Exception e) {
            log.error("Unable to fetch feed with ID {}", feedId, e);
        }
    }
}
