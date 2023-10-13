/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.commons.authuser.User;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomUser;
import static org.opensearch.securityanalytics.TestHelpers.randomUserEmpty;

public class WriteableTests extends OpenSearchTestCase {

    public void testDetectorAsStream() throws IOException {
        Detector detector = randomDetector(List.of());
        detector.setInputs(List.of(new DetectorInput("", List.of(), List.of(), List.of())));
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
                List.of(new LogType.Mapping("rawField", null, null)),
                List.of(new LogType.IocFields("ip", List.of("dst.ip")))
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
                List.of(new LogType.Mapping("rawField", "some_ecs_field", "some_ocsf_field")),
                List.of(new LogType.IocFields("ip", List.of("dst.ip")))
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
        LogType logType = new LogType("1", "my_log_type", "description", false, null, null);
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