/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.common;

import org.opensearch.Version;

import java.util.Locale;
public class Constants {
    public static final String USER_AGENT_KEY = "User-Agent";
    public static final String USER_AGENT_VALUE = String.format(Locale.ROOT, "OpenSearch/%s vanilla", Version.CURRENT.toString());
    public static final String THREAT_INTEL_SOURCE_CONFIG_ID = "threat_intel_source_config_id";
}
