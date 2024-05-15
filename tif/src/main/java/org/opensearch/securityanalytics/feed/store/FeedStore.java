/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.feed.store;

import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.model.IOC;

import java.util.List;

public interface FeedStore {
    /**
     * Accepts a list of IOCs and stores them locally for use in feed processing
     *
     * @param iocs - A list of the IOCs to store
     * @param updateType - The type of update to make to the underlying store
     */
    void storeIOCs(List<IOC> iocs, UpdateType updateType);
}
