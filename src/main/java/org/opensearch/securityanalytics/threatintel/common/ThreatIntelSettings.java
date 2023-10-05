/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.model.DetectorTrigger;

/**
 * Settings for threat intel datasource operations
 */
public class ThreatIntelSettings {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);


    /**
     * Default endpoint to be used in threat intel feed datasource creation API
     */
    public static final Setting<String> DATASOURCE_ENDPOINT = Setting.simpleString(
            "plugins.security_analytics.threatintel.datasource.endpoint",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv", //TODO: fix this endpoint
            new DatasourceEndpointValidator(),
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Default update interval to be used in threat intel datasource creation API
     */
    public static final Setting<Long> DATASOURCE_UPDATE_INTERVAL = Setting.longSetting(
            "plugins.security_analytics.threatintel.datasource.update_interval_in_days",
            3l,
            1l,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Bulk size for indexing threat intel feed data
     */
    public static final Setting<Integer> BATCH_SIZE = Setting.intSetting(
            "plugins.security_analytics.threatintel.datasource.batch_size",
            10000,
            1,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Timeout value for threat intel processor
     */
    public static final Setting<TimeValue> THREAT_INTEL_TIMEOUT = Setting.timeSetting(
            "plugins.security_analytics.threat_intel_timeout",
            TimeValue.timeValueSeconds(30),
            TimeValue.timeValueSeconds(1),
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Max size for threat intel feed cache
     */
    public static final Setting<Long> CACHE_SIZE = Setting.longSetting(
            "plugins.security_analytics.threatintel.processor.cache_size",
            1000,
            0,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Return all settings of threat intel feature
     * @return a list of all settings for threat intel feature
     */
    public static final List<Setting<?>> settings() {
        return List.of(DATASOURCE_ENDPOINT, DATASOURCE_UPDATE_INTERVAL, BATCH_SIZE, THREAT_INTEL_TIMEOUT);
    }
    protected static class DatasourceEndpointValidator implements Setting.Validator<String> {
        @Override
        public void validate(final String value) {
            try {
                new URL(value).toURI();
            } catch (MalformedURLException | URISyntaxException e) {
                log.error("Invalid URL format is provided", e);
                throw new IllegalArgumentException("Invalid URL format is provided");
            }
        }
    }
}
