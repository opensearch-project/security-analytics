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

    public void testThreatIntelAlertParse1() throws IOException {
        long now = System.currentTimeMillis();
        String threatIntelAlertString = "{\"id\":\"463723c8-abad-423e-8802-086e54e705ab\",\"version\":1,\"schema_version\":0," +
                "\"trigger_id\":\"match\",\"trigger_name\":\"match\",\"state\":\"ACTIVE\",\"error_message\":null," +
                "\"ioc_value\":\"ip2\",\"ioc_type\":\"ip\",\"severity\":\"severity\",\"action_execution_results\":[]," +
                "\"finding_ids\":[\"329f5ee1-c353-49e8-bac6-5638a554d955\"],\"start_time\":\"2024-06-26T11:02:55.71801Z\"," +
                "\"end_time\":null,\"acknowledged_time\":null,\"last_updated_time\":\"2024-06-26T11:02:55.71801Z\"}";
        XContentParser xcp = XContentType.JSON.xContent().createParser(
                xContentRegistry(),
                LoggingDeprecationHandler.INSTANCE, threatIntelAlertString
        );
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