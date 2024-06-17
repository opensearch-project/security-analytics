package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.opensearch.securityanalytics.threatIntel.iocscan.dto.IocScanContext;

import java.util.function.BiConsumer;

public interface IoCScanServiceInterface<Data> {

    void scanIoCs(
            IocScanContext<Data> iocScanContext,
            BiConsumer<Object, Exception> scanCallback
    );
}
