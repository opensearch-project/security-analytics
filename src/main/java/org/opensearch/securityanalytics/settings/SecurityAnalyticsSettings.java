/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.settings;

import java.util.concurrent.TimeUnit;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;

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

    public static final Setting<Boolean> IS_CORRELATION_INDEX_SETTING = Setting.boolSetting(CORRELATION_INDEX, false, Setting.Property.IndexScope);

    public static final Setting<TimeValue> CORRELATION_TIME_WINDOW = Setting.positiveTimeSetting(
            "plugins.security_analytics.correlation_time_window",
            new TimeValue(5, TimeUnit.MINUTES),
            Setting.Property.NodeScope, Setting.Property.Dynamic
    );
}