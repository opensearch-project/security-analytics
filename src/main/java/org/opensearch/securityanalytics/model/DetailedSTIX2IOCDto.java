/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * A data transfer object for <STIX2IOC> containing additional details.
 */
public class DetailedSTIX2IOCDto extends STIX2IOCDto implements Writeable, ToXContentObject {
    public static String NUM_FINDINGS_FIELD = "num_findings";
    private long numFindings = 0L;

    public DetailedSTIX2IOCDto(
            STIX2IOCDto ioc,
            Long numFindings
    ) {
        super(
                ioc.getId(),
                ioc.getName(),
                ioc.getType(),
                ioc.getValue(),
                ioc.getSeverity(),
                ioc.getCreated(),
                ioc.getModified(),
                ioc.getDescription(),
                ioc.getLabels(),
                ioc.getFeedId(),
                ioc.getSpecVersion(),
                ioc.getVersion()
        );
        this.numFindings = numFindings;
    }

    public DetailedSTIX2IOCDto(StreamInput sin) throws IOException {
        this(STIX2IOCDto.readFrom(sin), sin.readLong());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeLong(numFindings);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(STIX2IOC.ID_FIELD, super.getId())
                .field(STIX2IOC.NAME_FIELD, super.getName())
                .field(STIX2IOC.TYPE_FIELD, super.getType())
                .field(STIX2IOC.VALUE_FIELD, super.getValue())
                .field(STIX2IOC.SEVERITY_FIELD, super.getSeverity())
                .timeField(STIX2IOC.CREATED_FIELD, super.getCreated())
                .timeField(STIX2IOC.MODIFIED_FIELD, super.getModified())
                .field(STIX2IOC.DESCRIPTION_FIELD, super.getDescription())
                .field(STIX2IOC.LABELS_FIELD, super.getLabels())
                .field(STIX2IOC.FEED_ID_FIELD, super.getFeedId())
                .field(STIX2IOC.SPEC_VERSION_FIELD, super.getSpecVersion())
                .field(STIX2IOC.VERSION_FIELD, super.getVersion())
                .field(NUM_FINDINGS_FIELD, numFindings)
                .endObject();
    }

    public long getNumFindings() {
        return numFindings;
    }

    public void setNumFindings(Long numFindings) {
        this.numFindings = numFindings;
    }
}
