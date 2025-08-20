package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.commons.connector.codec.InputCodec;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.service.JsonPathIocSchemaThreatIntelHandler;

import java.io.InputStream;
import java.util.List;
import java.util.function.Consumer;

/**
 * An implementation of InputCodec used to parse input stream using JsonPath notations from {@link JsonPathIocSchema} and build a list of {@link STIX2IOC} objects
 */
public class JsonPathAwareInputCodec implements InputCodec<STIX2IOC> {
    private static final Logger logger = LogManager.getLogger(JsonPathAwareInputCodec.class);
    private final SATIFSourceConfig satifSourceConfig;

    public JsonPathAwareInputCodec(SATIFSourceConfig satifSourceConfig) {
        this.satifSourceConfig = satifSourceConfig;
    }

    @Override
    public void parse(final InputStream inputStream, final Consumer<STIX2IOC> consumer) {
        try {
            List<STIX2IOC> stix2IOCS = JsonPathIocSchemaThreatIntelHandler.parseCustomSchema(
                    (JsonPathIocSchema) satifSourceConfig.getIocSchema(), inputStream, satifSourceConfig.getName(), satifSourceConfig.getId());
            stix2IOCS.forEach(ioc -> {
                try {
                    consumer.accept(ioc);
                } catch (Exception e) {
                    logger.error(String.format("Error while indexing STIX2Ioc - type [%s], value [%s]"), e);
                }
            });
        } catch (Exception e) {
            logger.error(String.format("Error while downloading and indexing STIX2Ioc"), e);
        }
    }
}
