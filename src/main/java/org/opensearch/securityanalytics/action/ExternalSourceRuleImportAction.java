package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class ExternalSourceRuleImportAction extends ActionType<ExternalSourceRuleImportResponse> {

    public static final ExternalSourceRuleImportAction INSTANCE = new ExternalSourceRuleImportAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/rule/external_import";

    public ExternalSourceRuleImportAction() {
        super(NAME, ExternalSourceRuleImportResponse::new);

    }
}