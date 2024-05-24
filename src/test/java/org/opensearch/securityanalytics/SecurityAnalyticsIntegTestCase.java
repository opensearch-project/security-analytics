package org.opensearch.securityanalytics;

import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.util.Arrays;
import java.util.Collection;

public class SecurityAnalyticsIntegTestCase extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays.asList(
                    SecurityAnalyticsPlugin.class
                );
    }

    @Override
    protected boolean ignoreExternalCluster() {
        return true;
    }

}
