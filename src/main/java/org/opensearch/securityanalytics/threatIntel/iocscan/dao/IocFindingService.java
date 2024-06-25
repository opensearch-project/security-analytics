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
 * Data layer to perform CRUD operations for threat intel ioc match : store in system index.
 */
public class IocFindingService extends BaseEntityCrudService<IocFinding> {
    //TODO manage index rollover
    public static final String INDEX_NAME = ".opensearch-sap-ioc-findings";
    public static final String ENTITY_NAME = "ioc_finding";
    private static final Logger log = LogManager.getLogger(IocFindingService.class);
    private final Client client;
    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    public IocFindingService(final Client client, final ClusterService clusterService, final NamedXContentRegistry xContentRegistry) {
        super(client, clusterService, xContentRegistry, xContentRegistry1);
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
    }

    @Override
    public String getIndexName() {
        return INDEX_NAME;
    }

    @Override
    public String getEntityName() {
        return ENTITY_NAME;
    }

    @Override
    protected String getIndexMapping() {
        try {
            try (InputStream is = IocFindingService.class.getResourceAsStream("/mappings/ioc_match_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Failed to get the threat intel ioc match index mapping", e);
            throw new SecurityAnalyticsException("Failed to get the threat intel ioc match index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }
}