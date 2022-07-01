/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
// Generated from Condition.g4 by ANTLR 4.10.1
package org.opensearch.securityanalytics.rules.condition;
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link ConditionParser}.
 */
public interface ConditionListener extends ParseTreeListener {
    /**
     * Enter a parse tree produced by {@link ConditionParser#start}.
     * @param ctx the parse tree
     */
    void enterStart(ConditionParser.StartContext ctx);
    /**
     * Exit a parse tree produced by {@link ConditionParser#start}.
     * @param ctx the parse tree
     */
    void exitStart(ConditionParser.StartContext ctx);
    /**
     * Enter a parse tree produced by the {@code orExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void enterOrExpression(ConditionParser.OrExpressionContext ctx);
    /**
     * Exit a parse tree produced by the {@code orExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void exitOrExpression(ConditionParser.OrExpressionContext ctx);
    /**
     * Enter a parse tree produced by the {@code andExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void enterAndExpression(ConditionParser.AndExpressionContext ctx);
    /**
     * Exit a parse tree produced by the {@code andExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void exitAndExpression(ConditionParser.AndExpressionContext ctx);
    /**
     * Enter a parse tree produced by the {@code identifierExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void enterIdentifierExpression(ConditionParser.IdentifierExpressionContext ctx);
    /**
     * Exit a parse tree produced by the {@code identifierExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void exitIdentifierExpression(ConditionParser.IdentifierExpressionContext ctx);
    /**
     * Enter a parse tree produced by the {@code notExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void enterNotExpression(ConditionParser.NotExpressionContext ctx);
    /**
     * Exit a parse tree produced by the {@code notExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void exitNotExpression(ConditionParser.NotExpressionContext ctx);
    /**
     * Enter a parse tree produced by the {@code parenExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void enterParenExpression(ConditionParser.ParenExpressionContext ctx);
    /**
     * Exit a parse tree produced by the {@code parenExpression}
     * labeled alternative in {@link ConditionParser#expression}.
     * @param ctx the parse tree
     */
    void exitParenExpression(ConditionParser.ParenExpressionContext ctx);
}