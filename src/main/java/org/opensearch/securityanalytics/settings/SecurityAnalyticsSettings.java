/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.unit.TimeValue;

public class SecurityAnalyticsSettings {

    public static Setting<TimeValue> INDEX_TIMEOUT = Setting.positiveTimeSetting("plugins.security_analytics.index_timeout",
            TimeValue.timeValueSeconds(60),
            Setting.Property.NodeScope, Setting.Property.Dynamic);

    public static Setting<Boolean>  FILTER_BY_BACKEND_ROLES = Setting.boolSetting(
            "plugins.security_analytics.filter_by_backend_roles",
            false,
            Setting.Property.NodeScope, Setting.Property.Dynamic);
}