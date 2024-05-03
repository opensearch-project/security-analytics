package org.opensearch.securityanalytics.connector;

import org.opensearch.securityanalytics.model.IOC;

import java.util.List;

public interface IOCConnector {
    /**
     * Loads a list of IOCs from a storage system
     *
     * @return List<IOC> a list of the retrieved IOCs
     */
    List<IOC> loadIOCs();
}
