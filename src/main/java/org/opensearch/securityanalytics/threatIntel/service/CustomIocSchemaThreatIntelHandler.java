package org.opensearch.securityanalytics.threatIntel.service;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.collect.Tuple;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.model.CustomSchemaIocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.apache.logging.log4j.util.Strings.isBlank;

public class CustomIocSchemaThreatIntelHandler {
    public static final Logger log = LogManager.getLogger(CustomIocSchemaThreatIntelHandler.class);

    /**
     * Parses the Iocs based on the JsonPath notation in {@link SATIFSourceConfig#getIocSchema()}
     * and extracts iocs from the JSON string {@link CustomSchemaIocUploadSource#getIocs()}
     * <p>
     * Method can support parsing two types of variations:
     * values and types are tuples i.e. there are equal number of tuples
     *
     * @return
     */
    public static List<STIX2IOC> parseCustomSchema(SATIFSourceConfig saTifSourceConfig) {
        //TODO handle s3 download
        CustomSchemaIocUploadSource source = (CustomSchemaIocUploadSource) saTifSourceConfig.getSource();
        if (isBlank(source.getIocs())) {
            log.error("Ioc Schema set as null when creating {} source config name {}.",
                    saTifSourceConfig.getType(), saTifSourceConfig.getName()
            );
            throw new IllegalArgumentException(String.format(saTifSourceConfig.getName(), "Iocs cannot be empty when creating/updating %s source config."));

        }
        if (saTifSourceConfig.getIocSchema() == null) {
            log.error("Ioc Schema set as null when creating {} source config [{}].",
                    saTifSourceConfig.getType(), saTifSourceConfig.getName()
            );
            throw new IllegalArgumentException(String.format("Iocs cannot be null or empty when creating %s source config.", saTifSourceConfig.getName()));
        }
        JsonPathIocSchema iocSchema = (JsonPathIocSchema) saTifSourceConfig.getIocSchema();
        if (iocSchema.getValue() == null || isBlank(iocSchema.getValue().getJsonPath())
                || iocSchema.getType() == null || isBlank(iocSchema.getType().getJsonPath())
        ) {
            log.error("Custom Format Ioc Schema is missing the json path notation to extract ioc 'value' and/or" +
                            "ioc 'type' when parsing indicators from custom format threat intel source {}.",
                    saTifSourceConfig.getName()
            );
            throw new IllegalArgumentException(String.format("Custom Ioc Schema jsonPath notation for ioc 'value' and/or ioc 'type' cannot be blank"));
        }
        String iocs = source.getIocs();
        Configuration conf = Configuration.defaultConfiguration()
                .addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL)
                .addOptions(Option.ALWAYS_RETURN_LIST)
                .addOptions(Option.SUPPRESS_EXCEPTIONS);
        List<Tuple<String, String>> parsedTuples = new ArrayList<>();

        try {
            // Try to read as lists first
            // Use DocumentContext to parse the JSON once
            DocumentContext context = JsonPath.using(conf).parse(iocs);
            List<Object> valuesList = context.read(iocSchema.getValue().getJsonPath());
            List<Object> typesList = context.read(iocSchema.getType().getJsonPath());

            if (typesList.isEmpty() || typesList.stream().allMatch(Objects::isNull)) {
                throw new IllegalArgumentException("No valid ioc type parsed from custom schema threat intel source" + saTifSourceConfig.getName());
            } else if (valuesList.isEmpty() || valuesList.stream().allMatch(Objects::isNull)) {
                throw new IllegalArgumentException("No valid ioc value parsed from custom schema threat intel source" + saTifSourceConfig.getName());
            }
            // Handle case where we get lists of values and one type
            if (typesList.size() == 1 && false == isBlank(typesList.get(0).toString()) && valuesList.size() > 1) { // handle case where iocs json looks
                for (int i = 0; i < valuesList.size(); i++) {
                    List<String> valsList = handleIocValueFieldParsing(valuesList, i);
                    if (typesList.get(i) == null) {
                        log.error("Skipping parsing some iocs since type is null in threat intel source " + saTifSourceConfig.getName());
                        continue;
                    }
                    String type = String.valueOf(typesList.get(0));
                    if (isBlank(type)) {
                        log.error("Skipping parsing some iocs since type is blank in threat intel source " + saTifSourceConfig.getName());
                        continue;
                    }
                    for (String value : valsList) {
                        if (!isBlank(value)) {
                            parsedTuples.add(new Tuple<>(type, value));
                        }
                    }
                }
            } else {
                for (int i = 0; i < Math.min(valuesList.size(), typesList.size()); i++) { // since we are building tuples manually from json annotation we will assume 1:1 mapping of ioc type ot ioc value
                    List<String> valsList = handleIocValueFieldParsing(valuesList, i);
                    if (typesList.get(i) == null) {
                        log.error("Skipping parsing some iocs since type is null in threat intel source " + saTifSourceConfig.getName());
                        continue;
                    }
                    String type = String.valueOf(typesList.get(i));
                    if (isBlank(type)) {
                        log.error("Skipping parsing some iocs since type is blank in threat intel source " + saTifSourceConfig.getName());
                        continue;
                    }
                    for (String value : valsList) {
                        if (!isBlank(value)) {
                            parsedTuples.add(new Tuple<>(type, value));
                        }
                    }
                }
            }

        } catch (Exception ex) {
            log.error(String.format("Unexpected failure while parsing custom ioc schema threat intel source %s", saTifSourceConfig.getName()), ex);
            throw new IllegalArgumentException("Failed to parse threat intel ioc JSON with provided paths for source " + saTifSourceConfig.getName(), ex);
        }

        if (parsedTuples.isEmpty()) {
            log.error("No valid IOCs found while parsing custom ioc schema threat intel source " + saTifSourceConfig.getName());
            throw new IllegalArgumentException("No valid IOCs found while parsing custom ioc schema threat intel source " + saTifSourceConfig.getName());
        }

        return parsedTuples.stream().map(it -> getStix2IOC(saTifSourceConfig, it)).collect(Collectors.toList());
    }

    /**
     * Handle Ioc Value being an array or single field
     */
    private static List<String> handleIocValueFieldParsing(List<Object> valuesList, int i) {
        List<String> valsList = new ArrayList<>();
        if (valuesList.get(i) instanceof List) { // handle case where the value is a list of ioc-values encompassed in an array like "<value>" : ["1.2.3.4", "0.0.0.0"]
            valsList.addAll(((List<String>) valuesList.get(i)));
        } else if (valuesList.get(i) instanceof String) {  // handle case where the value is a string with a single ioc-value  like "<value>" : "1.2.3.4"
            String value = String.valueOf(valuesList.get(i));
            valsList.add(value);
        }
        return valsList;
    }

    private static STIX2IOC getStix2IOC(SATIFSourceConfig saTifSourceConfig, Tuple<String, String> it) {

        return new STIX2IOC(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                it.v1(),
                it.v2(),
                "",
                null,
                null,
                "",
                emptyList(),
                "",
                isBlank(saTifSourceConfig.getId()) ? null : saTifSourceConfig.getId(),
                saTifSourceConfig.getName(),
                1L
        );
    }


}
