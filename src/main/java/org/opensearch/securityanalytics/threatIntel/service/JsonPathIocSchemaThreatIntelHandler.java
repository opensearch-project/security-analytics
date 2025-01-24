package org.opensearch.securityanalytics.threatIntel.service;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.model.CustomSchemaIocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathIocSchema;
import org.opensearch.securityanalytics.threatIntel.model.JsonPathSchemaField;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Predicate;

import static java.util.Collections.emptyList;
import static org.apache.logging.log4j.util.Strings.isBlank;

public class JsonPathIocSchemaThreatIntelHandler {
    public static final Logger log = LogManager.getLogger(JsonPathIocSchemaThreatIntelHandler.class);

    /**
     * Common interface for handling different input types for IOC parsing
     */
    private interface IocInputHandler {
        DocumentContext getDocumentContext(Configuration conf) throws Exception;
    }

    /**
     * Handles String input for IOC parsing
     */
    private static class StringIocHandler implements IocInputHandler {
        private final String iocsJson;

        public StringIocHandler(String iocsJson) {
            this.iocsJson = iocsJson;
        }

        @Override
        public DocumentContext getDocumentContext(Configuration conf) {
            return JsonPath.using(conf).parse(iocsJson);
        }
    }

    /**
     * Handles InputStream input for IOC parsing
     */
    private static class InputStreamIocHandler implements IocInputHandler {
        private final InputStream inputStream;

        public InputStreamIocHandler(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public DocumentContext getDocumentContext(Configuration conf) {
            return JsonPath.using(conf).parse(inputStream);
        }
    }

    /**
     * Parses the IOCs based on the JsonPath notation in {@link SATIFSourceConfig#getIocSchema()}
     * and extracts IOCs from the JSON string {@link CustomSchemaIocUploadSource#getIocs()}
     *
     * @param iocSchema  The schema defining JSON paths for IOC fields
     * @param iocsJson   The JSON string containing IOC data
     * @param sourceName Name of the threat intel source
     * @param sourceId   ID of the threat intel source
     * @return List of parsed STIX2IOC objects
     */
    public static List<STIX2IOC> parseCustomSchema(JsonPathIocSchema iocSchema, String iocsJson, String sourceName, String sourceId) {
        return parseCustomSchemaInternal(iocSchema, new StringIocHandler(iocsJson), sourceName, sourceId);
    }

    /**
     * Parses the IOCs based on the JsonPath notation in {@link SATIFSourceConfig#getIocSchema()}
     * and extracts IOCs from the InputStream containing JSON data
     *
     * @param iocSchema   The schema defining JSON paths for IOC fields
     * @param inputStream The InputStream containing IOC data in JSON format
     * @param sourceName  Name of the threat intel source
     * @param sourceId    ID of the threat intel source
     * @return List of parsed STIX2IOC objects
     */
    public static List<STIX2IOC> parseCustomSchema(JsonPathIocSchema iocSchema, InputStream inputStream, String sourceName, String sourceId) {
        return parseCustomSchemaInternal(iocSchema, new InputStreamIocHandler(inputStream), sourceName, sourceId);
    }

    /**
     * Internal method that handles the common parsing logic for both String and InputStream inputs
     *
     * @param iocSchema    The schema defining JSON paths for IOC fields
     * @param inputHandler Handler for the input source (String or InputStream)
     * @param sourceName   Name of the threat intel source
     * @param sourceId     ID of the threat intel source
     * @return List of parsed STIX2IOC objects
     */
    private static List<STIX2IOC> parseCustomSchemaInternal(JsonPathIocSchema iocSchema, IocInputHandler inputHandler,
                                                            String sourceName, String sourceId) {
        //TODO handle s3 download

        Configuration conf = Configuration.defaultConfiguration()
                .addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL)
                .addOptions(Option.ALWAYS_RETURN_LIST)
                .addOptions(Option.SUPPRESS_EXCEPTIONS);

        try {

            // Use DocumentContext to parse the JSON once
            DocumentContext context = inputHandler.getDocumentContext(conf);
            List<Object> valuesList = context.read(iocSchema.getValue().getJsonPath());
            List<Object> typesList = context.read(iocSchema.getType().getJsonPath());
            List<String> ids = parseStringListFromJsonPathNotation(context, iocSchema.getId(), true, valuesList.size());
            List<String> names = parseStringListFromJsonPathNotation(context, iocSchema.getName(), true, valuesList.size());
            List<String> severityList = parseStringListFromJsonPathNotation(context, iocSchema.getSeverity(), false, valuesList.size());
            List<String> descriptionList = parseStringListFromJsonPathNotation(context, iocSchema.getDescription(), false, valuesList.size());
            List<String> specVersionList = parseStringListFromJsonPathNotation(context, iocSchema.getSpecVersion(), false, valuesList.size());
            List<Instant> createdList = parseInstantListFromJsonPathNotation(context, iocSchema.getCreated(), valuesList.size());
            List<Instant> modifiedList = parseInstantListFromJsonPathNotation(context, iocSchema.getModified(), valuesList.size());

            if (typesList.isEmpty() || typesList.stream().allMatch(objectIsNullOrNotString()) ) {
                throw new IllegalArgumentException("No valid ioc type parsed from custom schema threat intel source " + sourceName);
            } else if (valuesList.isEmpty() || valuesList.stream().allMatch(objectIsNullOrNotString())) {
                throw new IllegalArgumentException("No valid ioc value parsed from custom schema threat intel source " + sourceName);
            }
            // Handle case where we get lists of values and one type
            if (typesList.size() == 1 && isStringAndNonEmpty(typesList, 0) && valuesList.size() > 1) { // handle case where iocs json looks
                List<STIX2IOC> res = new ArrayList<>();
                for (int i = 0; i < valuesList.size(); i++) {
                    String type = String.valueOf(typesList.get(0));
                    List<String> valsList = handleIocValueFieldParsing(valuesList, i);
                    if (false == valsList.isEmpty()) {
                        String id = ids.get(i);
                        for (String value : valsList) {
                            res.add(new STIX2IOC(
                                    id,
                                    names.get(i),
                                    type,
                                    value,
                                    severityList.get(i),
                                    createdList.get(i),
                                    modifiedList.get(i),
                                    descriptionList.get(i),
                                    emptyList(),
                                    specVersionList.get(i),
                                    isBlank(sourceId) ? null : sourceId,
                                    sourceName,
                                    1L
                            ));
                            id = UUID.randomUUID().toString();
                        }
                    }

                }
                if (res.isEmpty()) {
                    log.error("No valid IOCs found while parsing custom ioc schema threat intel source " + sourceName);
                    throw new IllegalArgumentException("No valid IOCs found while parsing custom ioc schema threat intel source " + sourceName);
                }
                return res;
            } else {
                List<STIX2IOC> res = new ArrayList<>();
                for (int i = 0; i < Math.min(valuesList.size(), typesList.size()); i++) { // since we are building tuples manually from json annotation we will assume 1:1 mapping of ioc type ot ioc value
                    if (typesList.get(i) == null) {
                        log.error("Skipping parsing some iocs since type is null in threat intel source " + sourceName);
                        continue;
                    }
                    if(isStringAndNonEmpty(typesList, i)) {
                        log.error("Skipping parsing some iocs since type {} is not a string in threat intel source {}", typesList.get(i), sourceName);
                        continue;
                    }
                    String type = String.valueOf(typesList.get(i));
                    if (isBlank(type)) {
                        log.error("Skipping parsing some iocs since type is blank in threat intel source " + sourceName);
                        continue;
                    }
                    List<String> valsList = handleIocValueFieldParsing(valuesList, i);
                    if (false == valsList.isEmpty()) {
                        String id = ids.get(i);
                        for (String value : valsList) {
                            res.add(new STIX2IOC(
                                    id,
                                    names.get(i),
                                    type,
                                    value,
                                    severityList.get(i),
                                    createdList.get(i),
                                    modifiedList.get(i),
                                    descriptionList.get(i),
                                    emptyList(),
                                    specVersionList.get(i),
                                    isBlank(sourceId) ? null : sourceId,
                                    sourceName,
                                    1L
                            ));
                            id = UUID.randomUUID().toString();
                        }
                    }
                }
                if (res.isEmpty()) {
                    log.error("No valid IOCs found while parsing custom ioc schema threat intel source " + sourceName);
                    throw new IllegalArgumentException("No valid IOCs found while parsing custom ioc schema threat intel source " + sourceName);
                }
                return res;
            }

        } catch (Exception ex) {
            log.error(String.format("Unexpected failure while parsing custom ioc schema threat intel source %s", sourceName), ex);
            throw new IllegalArgumentException("Failed to parse threat intel ioc JSON with provided paths for source " + sourceName, ex);
        }
    }

    private static boolean isStringAndNonEmpty(List<Object> typesList, int index) {
        return typesList.get(index) instanceof String && false == isBlank(typesList.get(index).toString());
    }

    private static Predicate<Object> objectIsNullOrNotString() {
        return obj -> Objects.isNull(obj) || false == obj instanceof String;
    }

    private static List<String> parseStringListFromJsonPathNotation(DocumentContext context,
                                                                    JsonPathSchemaField schemaField,
                                                                    boolean replaceNullsWithRandom,
                                                                    int listSize) {
        List<String> res = new ArrayList<>();
        if (schemaField == null || schemaField.getJsonPath() == null) {
            for (int i = 0; i < listSize; i++) {
                if (replaceNullsWithRandom) {
                    res.add(UUID.randomUUID().toString());
                } else {
                    res.add(null);
                }
            }
            return res;
        }
        List<Object> fieldValues = context.read(schemaField.getJsonPath());
        if (fieldValues == null || fieldValues.isEmpty() || fieldValues.stream().allMatch(s -> s == null || isBlank(s.toString()))) {
            for (int i = 0; i < listSize; i++) {
                if (replaceNullsWithRandom) {
                    res.add(UUID.randomUUID().toString());
                } else {
                    res.add(null);
                }
            }
            return res;
        }
        for (int i = 0; i < listSize; i++) {
            if (fieldValues.get(i) == null) {
                if (replaceNullsWithRandom) {
                    res.add(UUID.randomUUID().toString());
                } else {
                    res.add(null);
                }
            } else if (fieldValues.get(i) instanceof String) {
                res.add(fieldValues.get(i).toString());
            } else {
                if (replaceNullsWithRandom) {
                    res.add(UUID.randomUUID().toString());
                } else {
                    res.add(null);
                }
            }
        }
        return res;
    }


    private static List<Instant> parseInstantListFromJsonPathNotation(DocumentContext context,
                                                                      JsonPathSchemaField schemaField,
                                                                      int listSize) {
        List<Instant> res = new ArrayList<>();
        if (schemaField == null || schemaField.getJsonPath() == null) {
            for (int i = 0; i < listSize; i++) {
                res.add(null);
            }
            return res;
        }

        List<Object> fieldValues = context.read(schemaField.getJsonPath());
        if (fieldValues == null || fieldValues.isEmpty() || fieldValues.stream().allMatch(s -> s == null || isBlank(s.toString()))) {
            for (int i = 0; i < listSize; i++) {
                res.add(null);
            }
            return res;
        }

        for (int i = 0; i < listSize; i++) {
            if (fieldValues.get(i) == null) {
                res.add(null);
            } else {
                try {
                    String value = fieldValues.get(i).toString();
                    res.add(Instant.parse(value));
                } catch (Exception ex) {
                    log.error(String.format("Failed to parse Instant value from json path notation [%s]", schemaField.getJsonPath()), ex);
                    res.add(null);
                }
            }
        }
        return res;
    }

    /**
     * Handle Ioc Value being an array or single field
     */
    private static List<String> handleIocValueFieldParsing(List<Object> valuesList, int i) {
        List<String> valsList = new ArrayList<>();
        if (valuesList.stream().allMatch(JsonPathIocSchemaThreatIntelHandler::nullOrBlank)) {
            return emptyList();
        }
        if (valuesList.get(i) instanceof List) { // handle case where the value is a list of ioc-values encompassed in an array like "<value>" : ["1.2.3.4", "0.0.0.0"]
            ((List<?>) valuesList.get(i)).stream().filter(it -> it instanceof String && !isBlank(it.toString())).forEach(it -> valsList.add(it.toString()));
        } else if (valuesList.get(i) instanceof String) {  // handle case where the value is a string with a single ioc-value  like "<value>" : "1.2.3.4"
            String value = String.valueOf(valuesList.get(i));
            valsList.add(value);
        }
        return valsList;
    }

    private static boolean nullOrBlank(Object it) {
        return it == null || isBlank(it.toString());
    }


}
