package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.commons.alerting.action.DocLevelMonitorFanOutResponse;
import org.opensearch.core.common.io.stream.Writeable;

/**
 * Ioc Scan Monitor fan out action that distributes the monitor runner logic to mutliple data node.
 */
public class IocScanMonitorFanOutAction extends ActionType<DocLevelMonitorFanOutResponse> {
    /**
     * @param name                                The name of the action, must be unique across actions.
     * @param docLevelMonitorFanOutResponseReader A reader for the response type
     */
    public IocScanMonitorFanOutAction(String name, Writeable.Reader<DocLevelMonitorFanOutResponse> docLevelMonitorFanOutResponseReader) {
        super(name, docLevelMonitorFanOutResponseReader);
    }

}