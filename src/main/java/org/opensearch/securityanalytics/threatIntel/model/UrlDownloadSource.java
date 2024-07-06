package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
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
    public static final String SOURCE_NAME = "URL_DOWNLOAD";

    private final URL url;

    public UrlDownloadSource(URL url) {
        this.url = url;
    }

    public UrlDownloadSource(StreamInput sin) throws IOException {
        this(new URL(sin.readString()));
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
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case URL_FIELD:
                    String urlString = xcp.text();
                    url = new URL(urlString);
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new UrlDownloadSource(url);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .startObject(URL_DOWNLOAD_FIELD)
                .field(URL_FIELD, url)
                .endObject()
                .endObject();
    }
}
