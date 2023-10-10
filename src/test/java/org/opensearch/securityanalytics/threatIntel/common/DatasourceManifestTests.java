/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.common;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLConnection;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

@SuppressForbidden(reason = "unit test")
public class DatasourceManifestTests extends SecurityAnalyticsRestTestCase {

    public void testInternalBuild_whenCalled_thenCorrectUserAgentValueIsSet() throws IOException {
        URLConnection connection = mock(URLConnection.class);
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        when(connection.getInputStream()).thenReturn(new FileInputStream(manifestFile));

        // Run
        DatasourceManifest manifest = DatasourceManifest.Builder.internalBuild(connection);

        // Verify
        verify(connection).addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
        assertEquals("https://test.com/db.zip", manifest.getUrl());
    }
}

