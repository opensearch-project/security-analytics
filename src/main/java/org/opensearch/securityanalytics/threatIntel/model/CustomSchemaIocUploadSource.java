package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class CustomSchemaIocUploadSource extends Source implements Writeable, ToXContent {
    public static final String IOCS_FIELD = "iocs";
    public static final String FILE_NAME_FIELD = "file_name";
    private String fileName;
    private String iocs;

    public CustomSchemaIocUploadSource(String fileName, String iocs) {
        this.fileName = fileName;
        this.iocs = iocs;
    }

    public CustomSchemaIocUploadSource(StreamInput sin) throws IOException {
        this (
                sin.readOptionalString(), // file name
                sin.readOptionalString() // iocs
        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(fileName);
        out.writeOptionalString(iocs);
    }

    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startObject(CUSTOM_SCHEMA_IOC_UPLOAD_FIELD);
        if (fileName != null) {
            builder.field(FILE_NAME_FIELD, fileName);
        }
        if(iocs != null) {
            builder.field(IOCS_FIELD, iocs);
        }
        builder.endObject();
        builder.endObject();
        return builder;
    }

    @Override
    String name() {
        return CUSTOM_SCHEMA_IOC_UPLOAD_FIELD;
    }

    public static CustomSchemaIocUploadSource parse(XContentParser xcp) throws IOException {
        String fileName = null;
        String iocs = null;

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case FILE_NAME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        fileName = null;
                    } else {
                        fileName = xcp.text();
                    }
                    break;
                case IOCS_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocs = null;
                    } else {
                        iocs = xcp.text();
                    }
                    break;
                default:
                    break;
            }
        }
        return new CustomSchemaIocUploadSource(fileName, iocs);
    }

    public String getIocs() {
        return iocs;
    }

    public void setIocs(String iocs) {
        this.iocs = iocs;
    }

    public String getFileName() {
        return fileName;
    }
}
