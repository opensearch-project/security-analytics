/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.common;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;

/**
 * Settings for Ip2Geo datasource operations
 */
public class ThreatIntelSettings {

    /**
     * Default endpoint to be used in threatIP datasource creation API
     */
    public static final Setting<String> DATASOURCE_ENDPOINT = Setting.simpleString(
            "plugins.securityanalytics.threatintel.datasource.endpoint",
            "https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json",
            new DatasourceEndpointValidator(),
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Default update interval to be used in Ip2Geo datasource creation API
     */
    public static final Setting<Long> DATASOURCE_UPDATE_INTERVAL = Setting.longSetting(
            "plugins.geospatial.ip2geo.datasource.update_interval_in_days",
            3l,
            1l,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Bulk size for indexing GeoIP data
     */
    public static final Setting<Integer> BATCH_SIZE = Setting.intSetting(
            "plugins.geospatial.ip2geo.datasource.batch_size",
            10000,
            1,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Timeout value for Ip2Geo processor
     */
    public static final Setting<TimeValue> TIMEOUT = Setting.timeSetting(
            "plugins.geospatial.ip2geo.timeout",
            TimeValue.timeValueSeconds(30),
            TimeValue.timeValueSeconds(1),
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Max size for geo data cache
     */
    public static final Setting<Long> CACHE_SIZE = Setting.longSetting(
            "plugins.geospatial.ip2geo.processor.cache_size",
            1000,
            0,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

    /**
     * Return all settings of Ip2Geo feature
     * @return a list of all settings for Ip2Geo feature
     */
    public static final List<Setting<?>> settings() {
        return List.of(DATASOURCE_ENDPOINT, DATASOURCE_UPDATE_INTERVAL, BATCH_SIZE, TIMEOUT, CACHE_SIZE);
    }

    /**
     * Visible for testing
     */
    protected static class DatasourceEndpointValidator implements Setting.Validator<String> {
        @Override
        public void validate(final String value) {
            try {
                new URL(value).toURI();
            } catch (MalformedURLException | URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URL format is provided");
            }
        }
    }
}
