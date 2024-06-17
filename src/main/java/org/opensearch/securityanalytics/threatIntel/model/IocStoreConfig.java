package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Base class for the IOC store config that other implementations will extend from
 */
public abstract class IocStoreConfig {
    private static final Logger log = LogManager.getLogger(IocStoreConfig.class);
    abstract String name();
    static IocStoreConfig readFrom(StreamInput sin) throws IOException {
        Type type = sin.readEnum(Type.class);
        switch(type) {
            case DEFAULT:
                return new DefaultIocStoreConfig(sin);
            default:
                throw new IllegalStateException("Unexpected input [" + type + "] when reading ioc store config");
        }
    }

    static IocStoreConfig parse(XContentParser xcp) throws IOException {
        IocStoreConfig iocStoreConfig = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case "default":
                    iocStoreConfig = DefaultIocStoreConfig.parse(xcp);
                    break;
            }
        }

        return iocStoreConfig;
    }

    public void writeTo(StreamOutput out) throws IOException {}


    enum Type {
        DEFAULT();
        @Override
        public String toString() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

}
