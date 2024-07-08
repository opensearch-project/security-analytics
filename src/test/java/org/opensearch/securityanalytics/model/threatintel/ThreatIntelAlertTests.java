package org.opensearch.securityanalytics.model.threatintel;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

public class ThreatIntelAlertTests extends OpenSearchTestCase {

    public void testAlertAsStream() throws IOException {
        ThreatIntelAlert alert = getRandomAlert();
        BytesStreamOutput out = new BytesStreamOutput();
        alert.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        ThreatIntelAlert newThreatIntelAlert = new ThreatIntelAlert(sin);
        asserts(alert, newThreatIntelAlert);
    }

    private static void asserts(ThreatIntelAlert alert, ThreatIntelAlert newThreatIntelAlert) {
        assertEquals(alert.getId(), newThreatIntelAlert.getId());
        assertEquals(alert.getErrorMessage(), newThreatIntelAlert.getErrorMessage());
        assertEquals(alert.getSeverity(), newThreatIntelAlert.getSeverity());
        assertEquals(alert.getSchemaVersion(), newThreatIntelAlert.getSchemaVersion());
        assertEquals(alert.getTriggerName(), newThreatIntelAlert.getTriggerName());
        assertEquals(alert.getTriggerId(), newThreatIntelAlert.getTriggerId());
        assertEquals(alert.getMonitorId(), newThreatIntelAlert.getMonitorId());
        assertEquals(alert.getMonitorName(), newThreatIntelAlert.getMonitorName());
        assertEquals(alert.getVersion(), newThreatIntelAlert.getVersion());
        assertEquals(alert.getActionExecutionResults(), newThreatIntelAlert.getActionExecutionResults());
        assertEquals(alert.getStartTime(), newThreatIntelAlert.getStartTime());
        assertEquals(alert.getAcknowledgedTime(), newThreatIntelAlert.getAcknowledgedTime());
        assertEquals(alert.getState(), newThreatIntelAlert.getState());
        assertEquals(alert.getIocValue(), newThreatIntelAlert.getIocValue());
        assertEquals(alert.getIocType(), newThreatIntelAlert.getIocType());
        assertEquals(alert.getLastUpdatedTime(), newThreatIntelAlert.getLastUpdatedTime());
        assertTrue(alert.getFindingIds().containsAll(newThreatIntelAlert.getFindingIds()));
    }

    public void testThreatIntelAlertParse() throws IOException {
        long now = System.currentTimeMillis();
        String threatIntelAlertString = "{\n" +
                "  \"id\": \"example-id\",\n" +
                "  \"version\": 1,\n" +
                "  \"schema_version\": 1,\n" +
                "  \"user\": null,\n" +
                "  \"trigger_name\": \"example-trigger-name\",\n" +
                "  \"trigger_id\": \"example-trigger-id\",\n" +
                "  \"monitor_id\": \"example-monitor-id\",\n" +
                "  \"monitor_name\": \"example-monitor-name\",\n" +
                "  \"state\": \"ACTIVE\",\n" +
                "  \"start_time\": \"" + now + "\",\n" +
                "  \"end_time\": \"" + now + "\",\n" +
                "  \"acknowledged_time\": \"" + now + "\",\n" +
                "  \"last_updated_time\": \"" + now + "\",\n" +
                "  \"ioc_value\": \"" + now + "\",\n" +
                "  \"ioc_type\": \"" + now + "\",\n" +
                "  \"error_message\": \"example-error-message\",\n" +
                "  \"severity\": \"high\",\n" +
                "  \"action_execution_results\": [],\n" +
                "  \"finding_id\": [ \"f1\", \"f2\"]\n" +
                "}\n";
        
        ThreatIntelAlert alert = ThreatIntelAlert.parse(getParser(threatIntelAlertString), 1l);
        BytesStreamOutput out = new BytesStreamOutput();
        alert.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        ThreatIntelAlert newThreatIntelAlert = new ThreatIntelAlert(sin);
        asserts(alert, newThreatIntelAlert);
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }

    private static ThreatIntelAlert getRandomAlert() {
        return new ThreatIntelAlert(
                randomAlphaOfLength(10),
                randomLong(),
                randomLong(),
                new User(randomAlphaOfLength(10), List.of(randomAlphaOfLength(10)), List.of(randomAlphaOfLength(10)), List.of(randomAlphaOfLength(10))),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                Alert.State.ACKNOWLEDGED,
                Instant.now(),
                Instant.now(),
                Instant.now(),
                Instant.now(),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                Collections.emptyList(),
                List.of(randomAlphaOfLength(10), randomAlphaOfLength(10))
        );
    }
}