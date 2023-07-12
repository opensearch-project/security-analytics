/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class IndexDetectorResponse extends ActionResponse implements ToXContentObject {

    private String id;

    private Long version;

    private RestStatus status;

    private Detector detector;

    public IndexDetectorResponse(String id, Long version, RestStatus status, Detector detector) {
        super();
        this.id = id;
        this.version = version;
        this.status = status;
        this.detector = detector;
    }

    public IndexDetectorResponse(StreamInput sin) throws IOException {
        this(sin.readString(),
             sin.readLong(),
             sin.readEnum(RestStatus.class),
             Detector.readFrom(sin));
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeEnum(status);
        detector.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field(_ID, id)
            .field(_VERSION, version);
        builder.startObject("detector")
            .field(Detector.NAME_FIELD, detector.getName())
            .field(Detector.DETECTOR_TYPE_FIELD, detector.getDetectorType())
            .field(Detector.ENABLED_FIELD, detector.getEnabled())
            .field(Detector.SCHEDULE_FIELD, detector.getSchedule())
            .field(Detector.INPUTS_FIELD, detector.getInputs())
            .field(Detector.TRIGGERS_FIELD, detector.getTriggers())
            .field(Detector.LAST_UPDATE_TIME_FIELD, detector.getLastUpdateTime())
            .field(Detector.ENABLED_TIME_FIELD, detector.getEnabledTime())
            .endObject();
        return builder.endObject();
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public RestStatus getStatus() {
        return status;
    }

    public Detector getDetector() {
        return detector;
    }
}