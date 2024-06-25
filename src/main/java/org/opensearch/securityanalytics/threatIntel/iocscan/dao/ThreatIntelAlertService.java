package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class ThreatIntelAlertService extends BaseEntityCrudService<ThreatIntelAlert> {
    private static final Logger log = LogManager.getLogger(ThreatIntelAlertService.class);
    public static final String INDEX_NAME = ".opensearch-sap-threat-intel-alerts";

    public ThreatIntelAlertService(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry) {
        super(client, clusterService, xContentRegistry);
    }
    @Override
    protected String getIndexMapping() {
        try {
            try (InputStream is = IocFindingService.class.getResourceAsStream("/mappings/threat_intel_alert_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Failed to get the threat intel alert index mapping", e);
            throw new SecurityAnalyticsException("Failed to get the threat intel alert index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    @Override
    protected String getIndexName() {
        return INDEX_NAME;
    }

    @Override
    public String getEntityName() {
        return "threat_intel_alert";
    }
}
