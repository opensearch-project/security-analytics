/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.opensearch.security.spi.resources.client.ResourceSharingClient;

public class ResourceSharingUtils {

    public static final String DETECTOR_TYPE = "detector";
    public static final String CORRELATION_RULE_TYPE = "correlation-rule";

    public static boolean shouldUseResourceAuthz(String resourceType) {
        ResourceSharingClient client = ResourceSharingClientAccessor.getInstance().getResourceSharingClient();
        if (client == null) {
            return false;
        }
        return client.isFeatureEnabledForType(resourceType);
    }
}
