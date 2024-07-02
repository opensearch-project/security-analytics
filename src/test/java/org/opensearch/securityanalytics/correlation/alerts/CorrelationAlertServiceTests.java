/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.correlation.alerts;

import org.opensearch.client.Client;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertsList;
import org.opensearch.test.OpenSearchTestCase;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class CorrelationAlertServiceTests  extends OpenSearchTestCase {

    public void testGetActiveAlerts() {
        // Mock setup
        Client client = mock(Client.class);
        NamedXContentRegistry xContentRegistry = mock(NamedXContentRegistry.class);
        CorrelationAlertService alertsService = spy(new CorrelationAlertService(client, xContentRegistry));


        // Fake data
        String ruleId = "correlation_rule_id_123";
        long currentTime = System.currentTimeMillis();

        // Define a fake correlation alert
        CorrelationAlert correlationAlert = new CorrelationAlert(
                Collections.emptyList(),
                ruleId,
                "mock-rule",
                UUID.randomUUID().toString(),
                1L,
                1,
                null,
                "mock-trigger",
                Alert.State.ACTIVE,
                Instant.ofEpochMilli(currentTime).minusMillis(1000L),
                Instant.ofEpochMilli(currentTime).plusMillis(1000L),
                null,
                null,
                "high",
                new ArrayList<>()
        );

        List<CorrelationAlert> correlationAlerts = Collections.singletonList(correlationAlert);

        // Call getActiveAlerts
        alertsService.getActiveAlerts(ruleId, currentTime, new ActionListener<CorrelationAlertsList>() {
            @Override
            public void onResponse(CorrelationAlertsList correlationAlertsList) {
                // Assertion
                assertEquals(correlationAlerts.size(), correlationAlertsList.getCorrelationAlertList().size());

                // Additional assertions can be added here to verify specific fields or states
                CorrelationAlert returnedAlert = correlationAlertsList.getCorrelationAlertList().get(0);
                assertEquals(correlationAlert.getId(), returnedAlert.getId());
                assertEquals(correlationAlert.getCorrelationRuleId(), returnedAlert.getCorrelationRuleId());
                assertEquals(correlationAlert.getStartTime(), returnedAlert.getStartTime());
                assertEquals(correlationAlert.getEndTime(), returnedAlert.getEndTime());
            }

            @Override
            public void onFailure(Exception e) {

            }
        });
    }
}
