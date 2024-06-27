package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Data layer to perform CRUD operations for threat intel ioc finding : store in system index.
 */
public class IocFindingService extends BaseEntityCrudService<IocFinding> {

    public static final String IOC_FINDING_ALIAS_NAME = ".opensearch-sap-ioc-findings";

    public static final String IOC_FINDING_INDEX_PATTERN = "<.opensearch-sap-ioc-findings-history-{now/d}-1>";

    public static final String IOC_FINDING_INDEX_PATTERN_REGEXP = ".opensearch-sap-ioc-findings*";

    private static final Logger log = LogManager.getLogger(IocFindingService.class);
    private final Client client;
    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    public IocFindingService(final Client client, final ClusterService clusterService, final NamedXContentRegistry xContentRegistry) {
        super(client, clusterService, xContentRegistry);
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
    }

    @Override
    public String getEntityIndexMapping() {
        return getIndexMapping();
    }

    public static String getIndexMapping() {
        try {
            try (InputStream is = IocFindingService.class.getResourceAsStream("/mappings/ioc_finding_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Failed to get the threat intel ioc finding index mapping", e);
            throw new SecurityAnalyticsException("Failed to get the threat intel ioc finding index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }
    @Override
    public String getEntityAliasName() {
        return IOC_FINDING_ALIAS_NAME;
    }

    @Override
    public String getEntityIndexPattern() {
        return IOC_FINDING_INDEX_PATTERN;
    }

    @Override
    public String getEntityName() {
        return "ioc_finding";
    }
}