package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Base class for a source object that custom source configs will extend from
 */
public abstract class Source {
    private static final Logger log = LogManager.getLogger(Source.class);
    abstract String name();
    static Source readFrom(StreamInput sin) throws IOException {
        Type type = sin.readEnum(Type.class);
        switch(type) {
            case S3:
                return new S3Source(sin);
            default:
                throw new IllegalStateException("Unexpected input ["+ type + "] when reading ioc store config");
        }
    }

    static Source parse(XContentParser xcp) throws IOException {
        Source source = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case "s3":
                    source = S3Source.parse(xcp);
                    break;
            }
        }
        return source;
    }

    public void writeTo(StreamOutput out) throws IOException {}

    enum Type {
        S3();

        @Override
        public String toString() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

}
