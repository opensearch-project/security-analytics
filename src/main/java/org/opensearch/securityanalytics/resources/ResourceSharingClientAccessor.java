/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.opensearch.security.spi.resources.client.ResourceSharingClient;

public class ResourceSharingClientAccessor {
    private ResourceSharingClient client;
    private static ResourceSharingClientAccessor instance;

    private ResourceSharingClientAccessor() {}

    public static ResourceSharingClientAccessor getInstance() {
        if (instance == null) {
            instance = new ResourceSharingClientAccessor();
        }
        return instance;
    }

    public void setResourceSharingClient(ResourceSharingClient client) {
        this.client = client;
    }

    public ResourceSharingClient getResourceSharingClient() {
        return client;
    }
}
