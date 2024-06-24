package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;

public class ThreatIntelAlertService extends BaseEntityCrudService<ThreatIntelAlert> {

    public ThreatIntelAlertService(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry) {
        super(client, clusterService, xContentRegistry);
    }

    @Override
    protected String getIndexMapping() {
        return null; //TODO
    }

    @Override
    protected String getIndexName() {
        return ".opensearch-sap-threat-intel-alerts";
    }

    @Override
    public String getEntityName() {
        return "threat_intel_alert";
    }
}
