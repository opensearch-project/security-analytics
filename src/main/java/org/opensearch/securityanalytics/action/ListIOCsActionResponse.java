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
import org.opensearch.securityanalytics.model.DetailedSTIX2IOCDto;
import org.opensearch.securityanalytics.model.STIX2IOCDto;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class ListIOCsActionResponse extends ActionResponse implements ToXContentObject {
    public static String TOTAL_HITS_FIELD = "total";
    public static String HITS_FIELD = "iocs";

    public static ListIOCsActionResponse EMPTY_RESPONSE = new ListIOCsActionResponse(0, Collections.emptyList());

    private long totalHits;
    private List<DetailedSTIX2IOCDto> hits;

    public ListIOCsActionResponse(long totalHits, List<DetailedSTIX2IOCDto> hits) {
        super();
        this.totalHits = totalHits;
        this.hits = hits;
    }

    public ListIOCsActionResponse(StreamInput sin) throws IOException {
        this(sin.readInt(), sin.readList(DetailedSTIX2IOCDto::new));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeLong(totalHits);
        out.writeList(hits);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(TOTAL_HITS_FIELD, totalHits)
                .field(HITS_FIELD, hits)
                .endObject();
    }
}
