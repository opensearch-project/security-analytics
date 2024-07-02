// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition.aggregation;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class AggregationParser extends Parser {
    static { RuntimeMetaData.checkVersion("4.11.1", RuntimeMetaData.VERSION); }

    protected static final DFA[] _decisionToDFA;
    protected static final PredictionContextCache _sharedContextCache =
        new PredictionContextCache();
    public static final int
        GT=1, GE=2, LT=3, LE=4, EQ=5, COUNT=6, SUM=7, MIN=8, MAX=9, AVG=10, BY=11,
        LPAREN=12, RPAREN=13, DECIMAL=14, IDENTIFIER=15, WS=16;
    public static final int
        RULE_comparison_expr = 0, RULE_comparison_operand = 1, RULE_comp_operator = 2,
        RULE_agg_operator = 3, RULE_groupby_expr = 4, RULE_agg_expr = 5, RULE_numeric_entity = 6;
    private static String[] makeRuleNames() {
        return new String[] {
            "comparison_expr", "comparison_operand", "comp_operator", "agg_operator",
            "groupby_expr", "agg_expr", "numeric_entity"
        };
    }
    public static final String[] ruleNames = makeRuleNames();

    private static String[] makeLiteralNames() {
        return new String[] {
            null, "'>'", "'>='", "'<'", "'<='", "'=='", "'count'", "'sum'", "'min'",
            "'max'", "'avg'", "'by'", "'('", "')'"
        };
    }
    private static final String[] _LITERAL_NAMES = makeLiteralNames();
    private static String[] makeSymbolicNames() {
        return new String[] {
            null, "GT", "GE", "LT", "LE", "EQ", "COUNT", "SUM", "MIN", "MAX", "AVG",
            "BY", "LPAREN", "RPAREN", "DECIMAL", "IDENTIFIER", "WS"
        };
    }
    private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
    public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

    /**
     * @deprecated Use {@link #VOCABULARY} instead.
     */
    @Deprecated
    public static final String[] tokenNames;
    static {
        tokenNames = new String[_SYMBOLIC_NAMES.length];
        for (int i = 0; i < tokenNames.length; i++) {
            tokenNames[i] = VOCABULARY.getLiteralName(i);
            if (tokenNames[i] == null) {
                tokenNames[i] = VOCABULARY.getSymbolicName(i);
            }

            if (tokenNames[i] == null) {
                tokenNames[i] = "<INVALID>";
            }
        }
    }

    @Override
    @Deprecated
    public String[] getTokenNames() {
        return tokenNames;
    }

    @Override

    public Vocabulary getVocabulary() {
        return VOCABULARY;
    }

    @Override
    public String getGrammarFileName() { return "java-escape"; }

    @Override
    public String[] getRuleNames() { return ruleNames; }

    @Override
    public String getSerializedATN() { return _serializedATN; }

    @Override
    public ATN getATN() { return _ATN; }

    public AggregationParser(TokenStream input) {
        super(input);
        _interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Comparison_exprContext extends ParserRuleContext {
        public Comparison_exprContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_comparison_expr; }

        public Comparison_exprContext() { }
        public void copyFrom(Comparison_exprContext ctx) {
            super.copyFrom(ctx);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class ComparisonExpressionWithOperatorContext extends Comparison_exprContext {
        public List<Comparison_operandContext> comparison_operand() {
            return getRuleContexts(Comparison_operandContext.class);
        }
        public Comparison_operandContext comparison_operand(int i) {
            return getRuleContext(Comparison_operandContext.class,i);
        }
        public Comp_operatorContext comp_operator() {
            return getRuleContext(Comp_operatorContext.class,0);
        }
        public ComparisonExpressionWithOperatorContext(Comparison_exprContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterComparisonExpressionWithOperator(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitComparisonExpressionWithOperator(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitComparisonExpressionWithOperator(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Comparison_exprContext comparison_expr() throws RecognitionException {
        Comparison_exprContext _localctx = new Comparison_exprContext(_ctx, getState());
        enterRule(_localctx, 0, RULE_comparison_expr);
        try {
            _localctx = new ComparisonExpressionWithOperatorContext(_localctx);
            enterOuterAlt(_localctx, 1);
            {
            setState(14);
            comparison_operand();
            setState(15);
            comp_operator();
            setState(16);
            comparison_operand();
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Comparison_operandContext extends ParserRuleContext {
        public Agg_exprContext agg_expr() {
            return getRuleContext(Agg_exprContext.class,0);
        }
        public Comparison_operandContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_comparison_operand; }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterComparison_operand(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitComparison_operand(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitComparison_operand(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Comparison_operandContext comparison_operand() throws RecognitionException {
        Comparison_operandContext _localctx = new Comparison_operandContext(_ctx, getState());
        enterRule(_localctx, 2, RULE_comparison_operand);
        try {
            enterOuterAlt(_localctx, 1);
            {
            setState(18);
            agg_expr();
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Comp_operatorContext extends ParserRuleContext {
        public TerminalNode GT() { return getToken(AggregationParser.GT, 0); }
        public TerminalNode GE() { return getToken(AggregationParser.GE, 0); }
        public TerminalNode LT() { return getToken(AggregationParser.LT, 0); }
        public TerminalNode LE() { return getToken(AggregationParser.LE, 0); }
        public TerminalNode EQ() { return getToken(AggregationParser.EQ, 0); }
        public Comp_operatorContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_comp_operator; }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterComp_operator(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitComp_operator(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitComp_operator(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Comp_operatorContext comp_operator() throws RecognitionException {
        Comp_operatorContext _localctx = new Comp_operatorContext(_ctx, getState());
        enterRule(_localctx, 4, RULE_comp_operator);
        int _la;
        try {
            enterOuterAlt(_localctx, 1);
            {
            setState(20);
            _la = _input.LA(1);
            if ( !(((_la) & ~0x3f) == 0 && ((1L << _la) & 62L) != 0) ) {
            _errHandler.recoverInline(this);
            }
            else {
                if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
                _errHandler.reportMatch(this);
                consume();
            }
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Agg_operatorContext extends ParserRuleContext {
        public TerminalNode COUNT() { return getToken(AggregationParser.COUNT, 0); }
        public TerminalNode SUM() { return getToken(AggregationParser.SUM, 0); }
        public TerminalNode MIN() { return getToken(AggregationParser.MIN, 0); }
        public TerminalNode MAX() { return getToken(AggregationParser.MAX, 0); }
        public TerminalNode AVG() { return getToken(AggregationParser.AVG, 0); }
        public Agg_operatorContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_agg_operator; }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterAgg_operator(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitAgg_operator(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitAgg_operator(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Agg_operatorContext agg_operator() throws RecognitionException {
        Agg_operatorContext _localctx = new Agg_operatorContext(_ctx, getState());
        enterRule(_localctx, 6, RULE_agg_operator);
        int _la;
        try {
            enterOuterAlt(_localctx, 1);
            {
            setState(22);
            _la = _input.LA(1);
            if ( !(((_la) & ~0x3f) == 0 && ((1L << _la) & 1984L) != 0) ) {
            _errHandler.recoverInline(this);
            }
            else {
                if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
                _errHandler.reportMatch(this);
                consume();
            }
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Groupby_exprContext extends ParserRuleContext {
        public TerminalNode IDENTIFIER() { return getToken(AggregationParser.IDENTIFIER, 0); }
        public Groupby_exprContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_groupby_expr; }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterGroupby_expr(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitGroupby_expr(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitGroupby_expr(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Groupby_exprContext groupby_expr() throws RecognitionException {
        Groupby_exprContext _localctx = new Groupby_exprContext(_ctx, getState());
        enterRule(_localctx, 8, RULE_groupby_expr);
        try {
            enterOuterAlt(_localctx, 1);
            {
            setState(24);
            match(IDENTIFIER);
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Agg_exprContext extends ParserRuleContext {
        public Agg_exprContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_agg_expr; }

        public Agg_exprContext() { }
        public void copyFrom(Agg_exprContext ctx) {
            super.copyFrom(ctx);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class AggExpressionNumericEntityContext extends Agg_exprContext {
        public Numeric_entityContext numeric_entity() {
            return getRuleContext(Numeric_entityContext.class,0);
        }
        public AggExpressionNumericEntityContext(Agg_exprContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterAggExpressionNumericEntity(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitAggExpressionNumericEntity(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitAggExpressionNumericEntity(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class AggExpressionParensContext extends Agg_exprContext {
        public Agg_operatorContext agg_operator() {
            return getRuleContext(Agg_operatorContext.class,0);
        }
        public TerminalNode LPAREN() { return getToken(AggregationParser.LPAREN, 0); }
        public Agg_exprContext agg_expr() {
            return getRuleContext(Agg_exprContext.class,0);
        }
        public TerminalNode RPAREN() { return getToken(AggregationParser.RPAREN, 0); }
        public TerminalNode BY() { return getToken(AggregationParser.BY, 0); }
        public Groupby_exprContext groupby_expr() {
            return getRuleContext(Groupby_exprContext.class,0);
        }
        public AggExpressionParensContext(Agg_exprContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterAggExpressionParens(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitAggExpressionParens(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitAggExpressionParens(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Agg_exprContext agg_expr() throws RecognitionException {
        Agg_exprContext _localctx = new Agg_exprContext(_ctx, getState());
        enterRule(_localctx, 10, RULE_agg_expr);
        int _la;
        try {
            setState(37);
            _errHandler.sync(this);
            switch (_input.LA(1)) {
            case COUNT:
            case SUM:
            case MIN:
            case MAX:
            case AVG:
                _localctx = new AggExpressionParensContext(_localctx);
                enterOuterAlt(_localctx, 1);
                {
                setState(26);
                agg_operator();
                setState(27);
                match(LPAREN);
                setState(28);
                agg_expr();
                setState(29);
                match(RPAREN);
                setState(31);
                _errHandler.sync(this);
                _la = _input.LA(1);
                if (_la==BY) {
                    {
                    setState(30);
                    match(BY);
                    }
                }

                setState(34);
                _errHandler.sync(this);
                _la = _input.LA(1);
                if (_la==IDENTIFIER) {
                    {
                    setState(33);
                    groupby_expr();
                    }
                }

                }
                break;
            case DECIMAL:
            case IDENTIFIER:
                _localctx = new AggExpressionNumericEntityContext(_localctx);
                enterOuterAlt(_localctx, 2);
                {
                setState(36);
                numeric_entity();
                }
                break;
            default:
                throw new NoViableAltException(this);
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    @SuppressWarnings("CheckReturnValue")
    public static class Numeric_entityContext extends ParserRuleContext {
        public Numeric_entityContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_numeric_entity; }

        public Numeric_entityContext() { }
        public void copyFrom(Numeric_entityContext ctx) {
            super.copyFrom(ctx);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class NumericConstContext extends Numeric_entityContext {
        public TerminalNode DECIMAL() { return getToken(AggregationParser.DECIMAL, 0); }
        public NumericConstContext(Numeric_entityContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterNumericConst(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitNumericConst(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitNumericConst(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class NumericVariableContext extends Numeric_entityContext {
        public TerminalNode IDENTIFIER() { return getToken(AggregationParser.IDENTIFIER, 0); }
        public NumericVariableContext(Numeric_entityContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).enterNumericVariable(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof AggregationListener ) ((AggregationListener)listener).exitNumericVariable(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof AggregationVisitor ) return ((AggregationVisitor<? extends T>)visitor).visitNumericVariable(this);
            else return visitor.visitChildren(this);
        }
    }

    public final Numeric_entityContext numeric_entity() throws RecognitionException {
        Numeric_entityContext _localctx = new Numeric_entityContext(_ctx, getState());
        enterRule(_localctx, 12, RULE_numeric_entity);
        try {
            setState(41);
            _errHandler.sync(this);
            switch (_input.LA(1)) {
            case DECIMAL:
                _localctx = new NumericConstContext(_localctx);
                enterOuterAlt(_localctx, 1);
                {
                setState(39);
                match(DECIMAL);
                }
                break;
            case IDENTIFIER:
                _localctx = new NumericVariableContext(_localctx);
                enterOuterAlt(_localctx, 2);
                {
                setState(40);
                match(IDENTIFIER);
                }
                break;
            default:
                throw new NoViableAltException(this);
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            exitRule();
        }
        return _localctx;
    }

    public static final String _serializedATN =
        "\u0004\u0001\u0010,\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002"+
        "\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002"+
        "\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0001\u0000\u0001\u0000\u0001"+
        "\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001\u0002\u0001\u0002\u0001"+
        "\u0003\u0001\u0003\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005\u0001"+
        "\u0005\u0001\u0005\u0001\u0005\u0003\u0005 \b\u0005\u0001\u0005\u0003"+
        "\u0005#\b\u0005\u0001\u0005\u0003\u0005&\b\u0005\u0001\u0006\u0001\u0006"+
        "\u0003\u0006*\b\u0006\u0001\u0006\u0000\u0000\u0007\u0000\u0002\u0004"+
        "\u0006\b\n\f\u0000\u0002\u0001\u0000\u0001\u0005\u0001\u0000\u0006\n("+
        "\u0000\u000e\u0001\u0000\u0000\u0000\u0002\u0012\u0001\u0000\u0000\u0000"+
        "\u0004\u0014\u0001\u0000\u0000\u0000\u0006\u0016\u0001\u0000\u0000\u0000"+
        "\b\u0018\u0001\u0000\u0000\u0000\n%\u0001\u0000\u0000\u0000\f)\u0001\u0000"+
        "\u0000\u0000\u000e\u000f\u0003\u0002\u0001\u0000\u000f\u0010\u0003\u0004"+
        "\u0002\u0000\u0010\u0011\u0003\u0002\u0001\u0000\u0011\u0001\u0001\u0000"+
        "\u0000\u0000\u0012\u0013\u0003\n\u0005\u0000\u0013\u0003\u0001\u0000\u0000"+
        "\u0000\u0014\u0015\u0007\u0000\u0000\u0000\u0015\u0005\u0001\u0000\u0000"+
        "\u0000\u0016\u0017\u0007\u0001\u0000\u0000\u0017\u0007\u0001\u0000\u0000"+
        "\u0000\u0018\u0019\u0005\u000f\u0000\u0000\u0019\t\u0001\u0000\u0000\u0000"+
        "\u001a\u001b\u0003\u0006\u0003\u0000\u001b\u001c\u0005\f\u0000\u0000\u001c"+
        "\u001d\u0003\n\u0005\u0000\u001d\u001f\u0005\r\u0000\u0000\u001e \u0005"+
        "\u000b\u0000\u0000\u001f\u001e\u0001\u0000\u0000\u0000\u001f \u0001\u0000"+
        "\u0000\u0000 \"\u0001\u0000\u0000\u0000!#\u0003\b\u0004\u0000\"!\u0001"+
        "\u0000\u0000\u0000\"#\u0001\u0000\u0000\u0000#&\u0001\u0000\u0000\u0000"+
        "$&\u0003\f\u0006\u0000%\u001a\u0001\u0000\u0000\u0000%$\u0001\u0000\u0000"+
        "\u0000&\u000b\u0001\u0000\u0000\u0000\'*\u0005\u000e\u0000\u0000(*\u0005"+
        "\u000f\u0000\u0000)\'\u0001\u0000\u0000\u0000)(\u0001\u0000\u0000\u0000"+
        "*\r\u0001\u0000\u0000\u0000\u0004\u001f\"%)";
    public static final ATN _ATN =
        new ATNDeserializer().deserialize(_serializedATN.toCharArray());
    static {
        _decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
        for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
            _decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
        }
    }
}