/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.IocDto;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class FetchIocsActionResponse extends ActionResponse implements ToXContentObject {
    public static String IOCS_FIELD = "iocs";
    public static String TOTAL_FIELD = "total";
    private List<IocDto> iocs = Collections.emptyList();

    public FetchIocsActionResponse(List<IOC> iocs) {
        super();
        iocs.forEach( ioc -> this.iocs.add(new IocDto(ioc)));
    }

    public FetchIocsActionResponse(StreamInput sin) throws IOException {
        this(sin.readList(IOC::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeList(iocs);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(IOCS_FIELD, this.iocs)
                .field(TOTAL_FIELD, this.iocs.size())
                .endObject();
    }

    public List<IocDto> getIocs() {
        return iocs;
    }
}
