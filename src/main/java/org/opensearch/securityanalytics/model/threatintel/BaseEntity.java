package org.opensearch.securityanalytics.model.threatintel;

import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

public abstract class BaseEntity implements Writeable, ToXContentObject {
    @Override
    public abstract void writeTo(StreamOutput out) throws IOException;

    @Override
    public abstract XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException;

    public abstract String getId();
}
