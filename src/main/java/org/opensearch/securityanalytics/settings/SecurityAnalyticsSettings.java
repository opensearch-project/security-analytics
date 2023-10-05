/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.settings;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelSettings;

public class SecurityAnalyticsSettings {
    public static final String CORRELATION_INDEX = "index.correlation";

    public static Setting<TimeValue> INDEX_TIMEOUT = Setting.positiveTimeSetting("plugins.security_analytics.index_timeout",
            TimeValue.timeValueSeconds(60),
            Setting.Property.NodeScope, Setting.Property.Dynamic);

    public static final Long DEFAULT_MAX_ACTIONABLE_ALERT_COUNT = 50L;

    public static final Setting<Boolean> ALERT_HISTORY_ENABLED = Setting.boolSetting(
            "plugins.security_analytics.alert_history_enabled",
            true,
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Boolean> FINDING_HISTORY_ENABLED = Setting.boolSetting(
            "plugins.security_analytics.alert_finding_enabled",
            true,
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> ALERT_HISTORY_ROLLOVER_PERIOD = Setting.positiveTimeSetting(
            "plugins.security_analytics.alert_history_rollover_period",
            TimeValue.timeValueHours(12),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> FINDING_HISTORY_ROLLOVER_PERIOD = Setting.positiveTimeSetting(
            "plugins.security_analytics.alert_finding_rollover_period",
            TimeValue.timeValueHours(12),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> ALERT_HISTORY_INDEX_MAX_AGE = Setting.positiveTimeSetting(
            "plugins.security_analytics.alert_history_max_age",
            new TimeValue(30, TimeUnit.DAYS),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> FINDING_HISTORY_INDEX_MAX_AGE = Setting.positiveTimeSetting(
            "plugins.security_analytics.finding_history_max_age",
            new TimeValue(30, TimeUnit.DAYS),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Long> ALERT_HISTORY_MAX_DOCS = Setting.longSetting(
            "plugins.security_analytics.alert_history_max_docs",
            1000L,
            0L,
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Long> FINDING_HISTORY_MAX_DOCS = Setting.longSetting(
            "plugins.security_analytics.alert_finding_max_docs",
            1000L,
            0L,
            Setting.Property.NodeScope, Setting.Property.Dynamic, Setting.Property.Deprecated
    );

    public static final Setting<TimeValue> ALERT_HISTORY_RETENTION_PERIOD = Setting.positiveTimeSetting(
            "plugins.security_analytics.alert_history_retention_period",
            new TimeValue(60, TimeUnit.DAYS),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> FINDING_HISTORY_RETENTION_PERIOD = Setting.positiveTimeSetting(
            "plugins.security_analytics.finding_history_retention_period",
            new TimeValue(60, TimeUnit.DAYS),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> REQUEST_TIMEOUT = Setting.positiveTimeSetting(
            "plugins.security_analytics.request_timeout",
            TimeValue.timeValueSeconds(10),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<TimeValue> MAX_ACTION_THROTTLE_VALUE = Setting.positiveTimeSetting(
            "plugins.security_analytics.action_throttle_max_value",
            TimeValue.timeValueHours(24),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Boolean> FILTER_BY_BACKEND_ROLES = Setting.boolSetting(
            "plugins.security_analytics.filter_by_backend_roles",
            false,
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Boolean> ENABLE_WORKFLOW_USAGE = Setting.boolSetting(
        "plugins.security_analytics.enable_workflow_usage",
        true,
        Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<Boolean> IS_CORRELATION_INDEX_SETTING = Setting.boolSetting(CORRELATION_INDEX, false, Setting.Property.IndexScope);

    public static final Setting<TimeValue> CORRELATION_TIME_WINDOW = Setting.positiveTimeSetting(
            "plugins.security_analytics.correlation_time_window",
            new TimeValue(5, TimeUnit.MINUTES),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    public static final Setting<String> DEFAULT_MAPPING_SCHEMA = Setting.simpleString(
            "plugins.security_analytics.mappings.default_schema",
            "ecs",
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );

    // threat intel settings
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
     * Max size for geo data cache
     */
    public static final Setting<Long> CACHE_SIZE = Setting.longSetting(
            "plugins.geospatial.ip2geo.processor.cache_size",
            1000,
            0,
            Setting.Property.NodeScope,
            Setting.Property.Dynamic
    );

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