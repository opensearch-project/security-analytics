package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.net.URL;

/**
 * This is a Threat Intel Source config where the iocs are downloaded from the URL
 */
public class UrlDownloadSource extends Source implements Writeable, ToXContent {
    public static final String URL_FIELD = "url";
    public static final String FEED_FORMAT_FIELD = "feed_format";
    public static final String HAS_CSV_HEADER_FIELD = "has_csv_header_field";
    public static final String CSV_IOC_VALUE_COLUMN_NUM_FIELD = "csv_ioc_value_colum_num";
    public static final String SOURCE_NAME = "URL_DOWNLOAD";

    private final URL url;
    private final String feedFormat;
    private final Boolean hasCsvHeader;
    private final Integer csvIocValueColumnNo;

    public UrlDownloadSource(URL url, String feedFormat, Boolean hasCsvHeader, Integer csvIocValueColumnNo) {
        this.url = url;
        this.feedFormat = feedFormat;
        this.hasCsvHeader = hasCsvHeader;
        this.csvIocValueColumnNo = csvIocValueColumnNo;

    }

    public UrlDownloadSource(StreamInput sin) throws IOException {
        this(
                new URL(sin.readString()),
                sin.readString(),
                sin.readOptionalBoolean(),
                sin.readOptionalInt()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(url.toString());
        out.writeString(feedFormat);
        out.writeOptionalBoolean(hasCsvHeader);
        out.writeOptionalInt(csvIocValueColumnNo);
    }

    @Override
    String name() {
        return SOURCE_NAME;
    }

    public URL getUrl() {
        return url;
    }

    public static UrlDownloadSource parse(XContentParser xcp) throws IOException {
        URL url = null;
        String feedFormat = null;
        Boolean hasCsvHeader = false;
        Integer csvIocValueColumnNo = null;
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case URL_FIELD:
                    String urlString = xcp.text();
                    url = new URL(urlString);
                    break;
                case FEED_FORMAT_FIELD:
                    feedFormat = xcp.text();
                    break;
                case HAS_CSV_HEADER_FIELD:
                    hasCsvHeader = xcp.booleanValue();
                    break;
                case CSV_IOC_VALUE_COLUMN_NUM_FIELD:
                    if (xcp.currentToken() == null)
                        xcp.skipChildren();
                    else
                        csvIocValueColumnNo = xcp.intValue();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new UrlDownloadSource(url, feedFormat, hasCsvHeader, csvIocValueColumnNo);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .startObject(URL_DOWNLOAD_FIELD)
                .field(URL_FIELD, url.toString())
                .field(FEED_FORMAT_FIELD, feedFormat)
                .field(HAS_CSV_HEADER_FIELD, hasCsvHeader)
                .field(CSV_IOC_VALUE_COLUMN_NUM_FIELD, csvIocValueColumnNo)
                .endObject()
                .endObject();
    }

    public String getFeedFormat() {
        return feedFormat;
    }

    public boolean hasCsvHeader() {
        return hasCsvHeader;
    }

    public Integer getCsvIocValueColumnNo() {
        return csvIocValueColumnNo;
    }
}
