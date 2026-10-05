/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.provider;

import java.util.List;

public interface RuleProvider {
    /**
     * A method to fetch RuleData from an external source
     *
     * @return - A list of RuleData used to parse the rules into the internal representation used for evaluation
     */
    List<RuleData> getRuleData();
}
