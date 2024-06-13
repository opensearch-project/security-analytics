/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.parser;
import static org.opensearch.securityanalytics.TestHelpers.randomIocDto;

public class IocDtoTests extends OpenSearchTestCase {
    public void testAsStream() throws IOException {
        IocDto ioc = randomIocDto();
        BytesStreamOutput out = new BytesStreamOutput();
        ioc.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocDto newIoc = new IocDto(sin);
        assertEqualIocDtos(ioc, newIoc);
    }

    public void testParseFunction() throws IOException {
        IocDto ioc = randomIocDto();
        String json = toJsonString(ioc);
        IocDto newIoc = IocDto.parse(parser(json), ioc.getId());
        assertEqualIocDtos(ioc, newIoc);
    }

    private String toJsonString(IocDto ioc) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = ioc.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    private void assertEqualIocDtos(IocDto ioc, IocDto newIoc) {
        assertEquals(ioc.getId(), newIoc.getId());
        assertEquals(ioc.getName(), newIoc.getName());
        assertEquals(ioc.getValue(), newIoc.getValue());
        assertEquals(ioc.getSeverity(), newIoc.getSeverity());
        assertEquals(ioc.getSpecVersion(), newIoc.getSpecVersion());
        assertEquals(ioc.getCreated(), newIoc.getCreated());
        assertEquals(ioc.getModified(), newIoc.getModified());
        assertEquals(ioc.getDescription(), newIoc.getDescription());
        assertEquals(ioc.getLabels(), newIoc.getLabels());
        assertEquals(ioc.getFeedId(), newIoc.getFeedId());
    }
}
