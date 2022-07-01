/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
// Generated from Condition.g4 by ANTLR 4.10.1
package org.opensearch.securityanalytics.rules.condition;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link ConditionParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface ConditionVisitor<T> extends ParseTreeVisitor<T> {
    /**
     * Visit a parse tree produced by {@link ConditionParser#start}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitStart(ConditionParser.StartContext ctx);
    /**
     * Visit a parse tree produced by the {@code orExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitOrExpression(ConditionParser.OrExpressionContext ctx);
    /**
     * Visit a parse tree produced by the {@code andExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitAndExpression(ConditionParser.AndExpressionContext ctx);
    /**
     * Visit a parse tree produced by the {@code identifierExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitIdentifierExpression(ConditionParser.IdentifierExpressionContext ctx);
    /**
     * Visit a parse tree produced by the {@code notExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitNotExpression(ConditionParser.NotExpressionContext ctx);
    /**
     * Visit a parse tree produced by the {@code parenExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitParenExpression(ConditionParser.ParenExpressionContext ctx);
}