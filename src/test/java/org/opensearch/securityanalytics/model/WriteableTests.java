/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.commons.authuser.User;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.parser;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomUser;
import static org.opensearch.securityanalytics.TestHelpers.randomUserEmpty;
import static org.opensearch.securityanalytics.TestHelpers.toJsonStringWithUser;

public class WriteableTests extends OpenSearchTestCase {

    public void testDetectorAsStream() throws IOException {
        Detector detector = randomDetector(List.of());
        detector.setInputs(List.of(new DetectorInput("", List.of(), List.of(), List.of())));
        logger.error(toJsonStringWithUser(detector));
        BytesStreamOutput out = new BytesStreamOutput();
        detector.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        Detector newDetector = new Detector(sin);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, newDetector);
    }

    public void testDetector() throws IOException { // an edge case of detector serialization that failed testDetectorAsAStream() intermittently
        String detectorString = "{\"type\":\"detector\",\"name\":\"MczAuRCrve\",\"detector_type\":\"test_windows\"," +
                "\"user\":{\"name\":\"QhKrfthgxw\",\"backend_roles\":[\"uYvGLCPhfX\",\"fOLkcRxMWR\"],\"roles\"" +
                ":[\"YuucNpVzTm\",\"all_access\"],\"custom_attribute_names\":[\"test_attr=test\"]," +
                "\"user_requested_tenant\":null},\"threat_intel_enabled\":false,\"enabled\":false,\"enabled_time\"" +
                ":null,\"schedule\":{\"period\":{\"interval\":5,\"unit\":\"MINUTES\"}},\"inputs\":[{\"detector_input\"" +
                ":{\"description\":\"\",\"indices\":[],\"custom_rules\":[],\"pre_packaged_rules\":[]}}],\"triggers\"" +
                ":[{\"id\":\"SiWfaosBBiNA8if0E1bC\",\"name\":\"windows-trigger\",\"severity\":\"1\",\"types\"" +
                ":[\"test_windows\"],\"ids\":[\"QuarksPwDump Clearing Access History\"],\"sev_levels\":[\"high\"]," +
                "\"tags\":[\"T0008\"],\"actions\":[],\"detection_types\":[\"rules\"]}],\"last_update_time\":" +
                "1698300892093,\"monitor_id\":[\"\"],\"workflow_ids\":[],\"bucket_monitor_id_rule_id\"" +
                ":{},\"rule_topic_index\":\"\",\"alert_index\":\"\",\"alert_history_index\":\"\"," +
                "\"alert_history_index_pattern\":\"\",\"findings_index\":\"\",\"findings_index_pattern\":\"\"}";
        Detector detector = Detector.parse(parser(detectorString), null, null);
//        Detector detector = randomDetector(List.of());
//        detector.setInputs(List.of(new DetectorInput("", List.of(), List.of(), List.of())));
//        logger.error(toJsonStringWithUser(detector));
        BytesStreamOutput out = new BytesStreamOutput();
        detector.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        Detector newDetector = new Detector(sin);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, newDetector);
    }

    public void testUserAsStream() throws IOException {
        User user = randomUser();
        BytesStreamOutput out = new BytesStreamOutput();
        user.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        User newUser = new User(sin);
        Assert.assertEquals("Round tripping User doesn't work", user, newUser);
    }

    public void testEmptyUserAsStream() throws IOException {
        User user = randomUserEmpty();
        BytesStreamOutput out = new BytesStreamOutput();
        user.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        User newUser = new User(sin);
        Assert.assertEquals("Round tripping User doesn't work", user, newUser);
    }

    public void testLogTypeAsStreamRawFieldOnly() throws IOException {
        LogType logType = new LogType(
                "1", "my_log_type", "description", false,
                List.of(new LogType.Mapping("rawField", null, null))
        );
        BytesStreamOutput out = new BytesStreamOutput();
        logType.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        LogType newLogType = new LogType(sin);
        assertEquals(logType.getName(), newLogType.getName());
        assertEquals(logType.getDescription(), newLogType.getDescription());
        assertEquals(logType.getIsBuiltIn(), newLogType.getIsBuiltIn());
        assertEquals(logType.getMappings().size(), newLogType.getMappings().size());
        assertEquals(logType.getMappings().get(0).getRawField(), newLogType.getMappings().get(0).getRawField());
    }

    public void testLogTypeAsStreamFull() throws IOException {
        LogType logType = new LogType(
                "1", "my_log_type", "description", false,
                List.of(new LogType.Mapping("rawField", "some_ecs_field", "some_ocsf_field"))
        );
        BytesStreamOutput out = new BytesStreamOutput();
        logType.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        LogType newLogType = new LogType(sin);
        assertEquals(logType.getName(), newLogType.getName());
        assertEquals(logType.getDescription(), newLogType.getDescription());
        assertEquals(logType.getIsBuiltIn(), newLogType.getIsBuiltIn());
        assertEquals(logType.getMappings().size(), newLogType.getMappings().size());
        assertEquals(logType.getMappings().get(0).getRawField(), newLogType.getMappings().get(0).getRawField());
    }

    public void testLogTypeAsStreamNoMappings() throws IOException {
        LogType logType = new LogType("1", "my_log_type", "description", false, null);
        BytesStreamOutput out = new BytesStreamOutput();
        logType.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        LogType newLogType = new LogType(sin);
        assertEquals(logType.getName(), newLogType.getName());
        assertEquals(logType.getDescription(), newLogType.getDescription());
        assertEquals(logType.getIsBuiltIn(), newLogType.getIsBuiltIn());
        assertEquals(logType.getMappings().size(), newLogType.getMappings().size());
    }
}