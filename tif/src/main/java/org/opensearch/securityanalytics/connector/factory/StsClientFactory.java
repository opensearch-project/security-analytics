/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.factory;

import org.opensearch.securityanalytics.factory.UnaryParameterCachingFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;

public class StsClientFactory extends UnaryParameterCachingFactory<String, StsClient> {
    @Override
    protected StsClient doCreate(final String region) {
        return StsClient.builder()
                .region(Region.of(region))
                .build();
    }
}
