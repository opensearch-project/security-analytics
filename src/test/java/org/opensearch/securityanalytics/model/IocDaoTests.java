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

import static org.opensearch.securityanalytics.TestHelpers.getParser;
import static org.opensearch.securityanalytics.TestHelpers.randomIocDao;

public class IocDaoTests extends OpenSearchTestCase {
    public void testAsStream() throws IOException {
        IocDao ioc = randomIocDao();
        BytesStreamOutput out = new BytesStreamOutput();
        ioc.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocDao newIoc = new IocDao(sin);
        assertEqualIocDaos(ioc, newIoc);
    }

    public void testParseFunction() throws IOException {
        IocDao ioc = randomIocDao();
        String json = toJsonString(ioc);
        IocDao newIoc = IocDao.parse(getParser(json), ioc.getId());
        assertEqualIocDaos(ioc, newIoc);
    }

    private String toJsonString(IocDao ioc) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = ioc.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    private void assertEqualIocDaos(IocDao ioc, IocDao newIoc) {
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
