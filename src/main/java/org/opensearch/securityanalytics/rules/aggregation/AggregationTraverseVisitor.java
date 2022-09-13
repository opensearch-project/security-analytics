/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.aggregation;

import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationBaseVisitor;
import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationParser;

public class AggregationTraverseVisitor extends AggregationBaseVisitor<AggregationItem> {

    private final AggregationItem aggregationItem;

    public AggregationTraverseVisitor() {
        this.aggregationItem = new AggregationItem();
    }

    @Override
    public AggregationItem visitComparisonExpressionWithOperator(AggregationParser.ComparisonExpressionWithOperatorContext ctx) {
        if (ctx.comp_operator() != null) {
            this.aggregationItem.setCompOperator(ctx.comp_operator().getText());
        }
        return super.visitComparisonExpressionWithOperator(ctx);
    }

    @Override
    public AggregationItem visitAggExpressionParens(AggregationParser.AggExpressionParensContext ctx) {
        if (ctx.agg_operator() != null) {
            this.aggregationItem.setAggFunction(ctx.agg_operator().getText());
        }
        return super.visitAggExpressionParens(ctx);
    }

    @Override
    public AggregationItem visitNumericConst(AggregationParser.NumericConstContext ctx) {
        if (ctx.DECIMAL() != null) {
            this.aggregationItem.setThreshold(Double.valueOf(ctx.DECIMAL().getText()));
        }
        return super.visitNumericConst(ctx);
    }

    @Override
    public AggregationItem visitNumericVariable(AggregationParser.NumericVariableContext ctx) {
        if (ctx.IDENTIFIER() != null) {
            this.aggregationItem.setAggField(ctx.IDENTIFIER().getText());
        }
        return super.visitNumericVariable(ctx);
    }

    @Override
    public AggregationItem visitGroupby_expr(AggregationParser.Groupby_exprContext ctx) {
        if(ctx.IDENTIFIER() != null) {
            this.aggregationItem.setGroupByField(ctx.IDENTIFIER().getText());
        }
        return super.visitGroupby_expr(ctx);
    }

    public AggregationItem getAggregationItem() {
        return aggregationItem;
    }
}