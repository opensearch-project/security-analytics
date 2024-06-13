// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition.aggregation;
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link AggregationParser}.
 */
public interface AggregationListener extends ParseTreeListener {
    /**
     * Enter a parse tree produced by the {@code ComparisonExpressionWithOperator}
     * labeled alternative in {@link AggregationParser#comparison_expr}.
     * @param ctx the parse tree
     */
    void enterComparisonExpressionWithOperator(AggregationParser.ComparisonExpressionWithOperatorContext ctx);
    /**
     * Exit a parse tree produced by the {@code ComparisonExpressionWithOperator}
     * labeled alternative in {@link AggregationParser#comparison_expr}.
     * @param ctx the parse tree
     */
    void exitComparisonExpressionWithOperator(AggregationParser.ComparisonExpressionWithOperatorContext ctx);
    /**
     * Enter a parse tree produced by {@link AggregationParser#comparison_operand}.
     * @param ctx the parse tree
     */
    void enterComparison_operand(AggregationParser.Comparison_operandContext ctx);
    /**
     * Exit a parse tree produced by {@link AggregationParser#comparison_operand}.
     * @param ctx the parse tree
     */
    void exitComparison_operand(AggregationParser.Comparison_operandContext ctx);
    /**
     * Enter a parse tree produced by {@link AggregationParser#comp_operator}.
     * @param ctx the parse tree
     */
    void enterComp_operator(AggregationParser.Comp_operatorContext ctx);
    /**
     * Exit a parse tree produced by {@link AggregationParser#comp_operator}.
     * @param ctx the parse tree
     */
    void exitComp_operator(AggregationParser.Comp_operatorContext ctx);
    /**
     * Enter a parse tree produced by {@link AggregationParser#agg_operator}.
     * @param ctx the parse tree
     */
    void enterAgg_operator(AggregationParser.Agg_operatorContext ctx);
    /**
     * Exit a parse tree produced by {@link AggregationParser#agg_operator}.
     * @param ctx the parse tree
     */
    void exitAgg_operator(AggregationParser.Agg_operatorContext ctx);
    /**
     * Enter a parse tree produced by {@link AggregationParser#groupby_expr}.
     * @param ctx the parse tree
     */
    void enterGroupby_expr(AggregationParser.Groupby_exprContext ctx);
    /**
     * Exit a parse tree produced by {@link AggregationParser#groupby_expr}.
     * @param ctx the parse tree
     */
    void exitGroupby_expr(AggregationParser.Groupby_exprContext ctx);
    /**
     * Enter a parse tree produced by the {@code AggExpressionParens}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     */
    void enterAggExpressionParens(AggregationParser.AggExpressionParensContext ctx);
    /**
     * Exit a parse tree produced by the {@code AggExpressionParens}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     */
    void exitAggExpressionParens(AggregationParser.AggExpressionParensContext ctx);
    /**
     * Enter a parse tree produced by the {@code AggExpressionNumericEntity}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     */
    void enterAggExpressionNumericEntity(AggregationParser.AggExpressionNumericEntityContext ctx);
    /**
     * Exit a parse tree produced by the {@code AggExpressionNumericEntity}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     */
    void exitAggExpressionNumericEntity(AggregationParser.AggExpressionNumericEntityContext ctx);
    /**
     * Enter a parse tree produced by the {@code NumericConst}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     */
    void enterNumericConst(AggregationParser.NumericConstContext ctx);
    /**
     * Exit a parse tree produced by the {@code NumericConst}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     */
    void exitNumericConst(AggregationParser.NumericConstContext ctx);
    /**
     * Enter a parse tree produced by the {@code NumericVariable}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     */
    void enterNumericVariable(AggregationParser.NumericVariableContext ctx);
    /**
     * Exit a parse tree produced by the {@code NumericVariable}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     */
    void exitNumericVariable(AggregationParser.NumericVariableContext ctx);
}