/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.test.OpenSearchTestCase;

public class ResourceSharingTests extends OpenSearchTestCase {

    @Override
    public void setUp() throws Exception {
        super.setUp();
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(null);
    }

    public void testGetClientReturnsNullWhenNotSet() {
        assertNull(ResourceSharingClientAccessor.getInstance().getResourceSharingClient());
    }

    public void testSetAndGetClient() {
        ResourceSharingClient mockClient = mock(ResourceSharingClient.class);
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(mockClient);
        assertSame(mockClient, ResourceSharingClientAccessor.getInstance().getResourceSharingClient());
    }

    public void testExtensionReturnsTwoProviders() {
        SecurityAnalyticsResourceSharingExtension ext = new SecurityAnalyticsResourceSharingExtension();
        Set<ResourceProvider> providers = ext.getResourceProviders();
        assertEquals(2, providers.size());
    }

    public void testDetectorProvider() {
        SecurityAnalyticsResourceSharingExtension ext = new SecurityAnalyticsResourceSharingExtension();
        ResourceProvider detectorProvider = ext.getResourceProviders().stream()
            .filter(p -> "detector".equals(p.resourceType()))
            .findFirst().orElseThrow();
        assertEquals(Detector.DETECTORS_INDEX, detectorProvider.resourceIndexName());
    }

    public void testCorrelationRuleProvider() {
        SecurityAnalyticsResourceSharingExtension ext = new SecurityAnalyticsResourceSharingExtension();
        ResourceProvider provider = ext.getResourceProviders().stream()
            .filter(p -> "correlation-rule".equals(p.resourceType()))
            .findFirst().orElseThrow();
        assertEquals(CorrelationRule.CORRELATION_RULE_INDEX, provider.resourceIndexName());
    }

    public void testAssignClient() {
        SecurityAnalyticsResourceSharingExtension ext = new SecurityAnalyticsResourceSharingExtension();
        ResourceSharingClient mockClient = mock(ResourceSharingClient.class);
        ext.assignResourceSharingClient(mockClient);
        assertSame(mockClient, ResourceSharingClientAccessor.getInstance().getResourceSharingClient());
    }

    public void testShouldUseResourceAuthzReturnsFalseWhenClientNull() {
        assertFalse(ResourceSharingUtils.shouldUseResourceAuthz("detector"));
    }

    public void testShouldUseResourceAuthzReturnsFalseWhenFeatureDisabled() {
        ResourceSharingClient mockClient = mock(ResourceSharingClient.class);
        when(mockClient.isFeatureEnabledForType("detector")).thenReturn(false);
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(mockClient);
        assertFalse(ResourceSharingUtils.shouldUseResourceAuthz("detector"));
    }

    public void testShouldUseResourceAuthzReturnsTrueWhenFeatureEnabled() {
        ResourceSharingClient mockClient = mock(ResourceSharingClient.class);
        when(mockClient.isFeatureEnabledForType("detector")).thenReturn(true);
        ResourceSharingClientAccessor.getInstance().setResourceSharingClient(mockClient);
        assertTrue(ResourceSharingUtils.shouldUseResourceAuthz("detector"));
    }
}
