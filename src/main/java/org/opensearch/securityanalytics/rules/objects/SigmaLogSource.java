/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.exceptions.SigmaLogsourceError;

import java.util.Map;

public class SigmaLogSource {

    private String product;

    private String category;

    private String service;

    public SigmaLogSource(String product, String category, String service) throws SigmaLogsourceError {
        this.product = product;
        this.category = category;
        this.service = service;

        if ((this.product == null || this.product.isEmpty()) && (this.category == null || this.category.isEmpty())
                && (this.service == null || this.service.isEmpty())) {
            throw new SigmaLogsourceError("Log source can't be empty");
        }
    }

    protected static SigmaLogSource fromDict(Map<String, Object> logSource) throws SigmaLogsourceError {
        String product = "";
        if (logSource.containsKey("product")) {
            product = logSource.get("product").toString();
        }

        String category = "";
        if (logSource.containsKey("category")) {
            category = logSource.get("category").toString();
        }

        String service = "";
        if (logSource.containsKey("service")) {
            service = logSource.get("service").toString();
        }
        return new SigmaLogSource(product, category, service);
    }

    public String getProduct() {
        return product;
    }

    public String getCategory() {
        return category;
    }

    public String getService() {
        return service;
    }
}