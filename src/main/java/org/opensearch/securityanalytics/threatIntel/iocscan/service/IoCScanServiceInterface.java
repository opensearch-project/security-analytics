package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.opensearch.commons.alerting.model.Finding;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;

import java.util.List;
import java.util.function.BiConsumer;

public interface IoCScanServiceInterface<Data> {

    void scanIoCs(
            IocScanContext<Data> iocScanContext,
            BiConsumer<Object, Exception> scanCallback
    );
}
