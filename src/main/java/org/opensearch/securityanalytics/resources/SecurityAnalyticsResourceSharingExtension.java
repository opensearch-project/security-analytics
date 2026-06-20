/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import java.util.Set;

import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;

public class SecurityAnalyticsResourceSharingExtension implements ResourceSharingExtension {

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(
            new ResourceProvider() {
                @Override
                public String resourceType() {
                    return "detector";
                }

                @Override
                public String resourceIndexName() {
                    return Detector.DETECTORS_INDEX;
                }
            },
            new ResourceProvider() {
                @Override
                public String resourceType() {
                    return "correlation-rule";
                }

                @Override
                public String resourceIndexName() {
                    return CorrelationRule.CORRELATION_RULE_INDEX;
                }
            }
        );
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(resourceSharingClient);
    }
}
