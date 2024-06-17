// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition.aggregation;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link AggregationParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface AggregationVisitor<T> extends ParseTreeVisitor<T> {
    /**
     * Visit a parse tree produced by the {@code ComparisonExpressionWithOperator}
     * labeled alternative in {@link AggregationParser#comparison_expr}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitComparisonExpressionWithOperator(AggregationParser.ComparisonExpressionWithOperatorContext ctx);
    /**
     * Visit a parse tree produced by {@link AggregationParser#comparison_operand}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitComparison_operand(AggregationParser.Comparison_operandContext ctx);
    /**
     * Visit a parse tree produced by {@link AggregationParser#comp_operator}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitComp_operator(AggregationParser.Comp_operatorContext ctx);
    /**
     * Visit a parse tree produced by {@link AggregationParser#agg_operator}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitAgg_operator(AggregationParser.Agg_operatorContext ctx);
    /**
     * Visit a parse tree produced by {@link AggregationParser#groupby_expr}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitGroupby_expr(AggregationParser.Groupby_exprContext ctx);
    /**
     * Visit a parse tree produced by the {@code AggExpressionParens}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitAggExpressionParens(AggregationParser.AggExpressionParensContext ctx);
    /**
     * Visit a parse tree produced by the {@code AggExpressionNumericEntity}
     * labeled alternative in {@link AggregationParser#agg_expr}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitAggExpressionNumericEntity(AggregationParser.AggExpressionNumericEntityContext ctx);
    /**
     * Visit a parse tree produced by the {@code NumericConst}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitNumericConst(AggregationParser.NumericConstContext ctx);
    /**
     * Visit a parse tree produced by the {@code NumericVariable}
     * labeled alternative in {@link AggregationParser#numeric_entity}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitNumericVariable(AggregationParser.NumericVariableContext ctx);
}