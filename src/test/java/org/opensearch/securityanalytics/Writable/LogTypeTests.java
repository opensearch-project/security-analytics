/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.Writable;

import java.io.IOException;
import java.util.List;
import org.junit.Test;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.securityanalytics.model.LogType;

import static org.opensearch.test.OpenSearchTestCase.assertEquals;

public class LogTypeTests {


    @Test
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

    @Test
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

    @Test
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
