/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.Serializable;

public abstract class IOC implements Serializable {
    public static final String FEED_ID_FIELD_NAME = "feedId";

    private String id;
    private String feedId;

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getFeedId() {
        return feedId;
    }

    public void setFeedId(final String feedId) {
        this.feedId = feedId;
    }
}
