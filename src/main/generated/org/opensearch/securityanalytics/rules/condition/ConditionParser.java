// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class ConditionParser extends Parser {
    static { RuntimeMetaData.checkVersion("4.11.1", RuntimeMetaData.VERSION); }

    protected static final DFA[] _decisionToDFA;
    protected static final PredictionContextCache _sharedContextCache =
        new PredictionContextCache();
    public static final int
        AND=1, OR=2, NOT=3, LPAREN=4, RPAREN=5, SELECTOR=6, IDENTIFIER=7, WHITESPACE=8;
    public static final int
        RULE_start = 0, RULE_expression = 1;
    private static String[] makeRuleNames() {
        return new String[] {
            "start", "expression"
        };
    }
    public static final String[] ruleNames = makeRuleNames();

    private static String[] makeLiteralNames() {
        return new String[] {
            null, "'and'", "'or'", "'not'", "'('", "')'"
        };
    }
    private static final String[] _LITERAL_NAMES = makeLiteralNames();
    private static String[] makeSymbolicNames() {
        return new String[] {
            null, "AND", "OR", "NOT", "LPAREN", "RPAREN", "SELECTOR", "IDENTIFIER",
            "WHITESPACE"
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

    public ConditionParser(TokenStream input) {
        super(input);
        _interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
    }

    @SuppressWarnings("CheckReturnValue")
    public static class StartContext extends ParserRuleContext {
        public ExpressionContext expression() {
            return getRuleContext(ExpressionContext.class,0);
        }
        public StartContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_start; }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterStart(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitStart(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitStart(this);
            else return visitor.visitChildren(this);
        }
    }

    public final StartContext start() throws RecognitionException {
        StartContext _localctx = new StartContext(_ctx, getState());
        enterRule(_localctx, 0, RULE_start);
        try {
            enterOuterAlt(_localctx, 1);
            {
            setState(4);
            expression(0);
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
    public static class ExpressionContext extends ParserRuleContext {
        public ExpressionContext(ParserRuleContext parent, int invokingState) {
            super(parent, invokingState);
        }
        @Override public int getRuleIndex() { return RULE_expression; }

        public ExpressionContext() { }
        public void copyFrom(ExpressionContext ctx) {
            super.copyFrom(ctx);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class OrExpressionContext extends ExpressionContext {
        public ExpressionContext left;
        public Token operator;
        public ExpressionContext right;
        public List<ExpressionContext> expression() {
            return getRuleContexts(ExpressionContext.class);
        }
        public ExpressionContext expression(int i) {
            return getRuleContext(ExpressionContext.class,i);
        }
        public TerminalNode OR() { return getToken(ConditionParser.OR, 0); }
        public OrExpressionContext(ExpressionContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterOrExpression(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitOrExpression(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitOrExpression(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class IdentOrSelectExpressionContext extends ExpressionContext {
        public TerminalNode SELECTOR() { return getToken(ConditionParser.SELECTOR, 0); }
        public TerminalNode IDENTIFIER() { return getToken(ConditionParser.IDENTIFIER, 0); }
        public IdentOrSelectExpressionContext(ExpressionContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterIdentOrSelectExpression(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitIdentOrSelectExpression(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitIdentOrSelectExpression(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class AndExpressionContext extends ExpressionContext {
        public ExpressionContext left;
        public Token operator;
        public ExpressionContext right;
        public List<ExpressionContext> expression() {
            return getRuleContexts(ExpressionContext.class);
        }
        public ExpressionContext expression(int i) {
            return getRuleContext(ExpressionContext.class,i);
        }
        public TerminalNode AND() { return getToken(ConditionParser.AND, 0); }
        public AndExpressionContext(ExpressionContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterAndExpression(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitAndExpression(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitAndExpression(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class NotExpressionContext extends ExpressionContext {
        public TerminalNode NOT() { return getToken(ConditionParser.NOT, 0); }
        public ExpressionContext expression() {
            return getRuleContext(ExpressionContext.class,0);
        }
        public NotExpressionContext(ExpressionContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterNotExpression(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitNotExpression(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitNotExpression(this);
            else return visitor.visitChildren(this);
        }
    }
    @SuppressWarnings("CheckReturnValue")
    public static class ParenExpressionContext extends ExpressionContext {
        public ExpressionContext inner;
        public TerminalNode LPAREN() { return getToken(ConditionParser.LPAREN, 0); }
        public TerminalNode RPAREN() { return getToken(ConditionParser.RPAREN, 0); }
        public ExpressionContext expression() {
            return getRuleContext(ExpressionContext.class,0);
        }
        public ParenExpressionContext(ExpressionContext ctx) { copyFrom(ctx); }
        @Override
        public void enterRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).enterParenExpression(this);
        }
        @Override
        public void exitRule(ParseTreeListener listener) {
            if ( listener instanceof ConditionListener ) ((ConditionListener)listener).exitParenExpression(this);
        }
        @Override
        public <T> T accept(ParseTreeVisitor<? extends T> visitor) {
            if ( visitor instanceof ConditionVisitor ) return ((ConditionVisitor<? extends T>)visitor).visitParenExpression(this);
            else return visitor.visitChildren(this);
        }
    }

    public final ExpressionContext expression() throws RecognitionException {
        return expression(0);
    }

    private ExpressionContext expression(int _p) throws RecognitionException {
        ParserRuleContext _parentctx = _ctx;
        int _parentState = getState();
        ExpressionContext _localctx = new ExpressionContext(_ctx, _parentState);
        ExpressionContext _prevctx = _localctx;
        int _startState = 2;
        enterRecursionRule(_localctx, 2, RULE_expression, _p);
        int _la;
        try {
            int _alt;
            enterOuterAlt(_localctx, 1);
            {
            setState(14);
            _errHandler.sync(this);
            switch (_input.LA(1)) {
            case SELECTOR:
            case IDENTIFIER:
                {
                _localctx = new IdentOrSelectExpressionContext(_localctx);
                _ctx = _localctx;
                _prevctx = _localctx;

                setState(7);
                _la = _input.LA(1);
                if ( !(_la==SELECTOR || _la==IDENTIFIER) ) {
                _errHandler.recoverInline(this);
                }
                else {
                    if ( _input.LA(1)==Token.EOF ) matchedEOF = true;
                    _errHandler.reportMatch(this);
                    consume();
                }
                }
                break;
            case LPAREN:
                {
                _localctx = new ParenExpressionContext(_localctx);
                _ctx = _localctx;
                _prevctx = _localctx;
                setState(8);
                match(LPAREN);
                setState(9);
                ((ParenExpressionContext)_localctx).inner = expression(0);
                setState(10);
                match(RPAREN);
                }
                break;
            case NOT:
                {
                _localctx = new NotExpressionContext(_localctx);
                _ctx = _localctx;
                _prevctx = _localctx;
                setState(12);
                match(NOT);
                setState(13);
                expression(3);
                }
                break;
            default:
                throw new NoViableAltException(this);
            }
            _ctx.stop = _input.LT(-1);
            setState(24);
            _errHandler.sync(this);
            _alt = getInterpreter().adaptivePredict(_input,2,_ctx);
            while ( _alt!=2 && _alt!=org.antlr.v4.runtime.atn.ATN.INVALID_ALT_NUMBER ) {
                if ( _alt==1 ) {
                    if ( _parseListeners!=null ) triggerExitRuleEvent();
                    _prevctx = _localctx;
                    {
                    setState(22);
                    _errHandler.sync(this);
                    switch ( getInterpreter().adaptivePredict(_input,1,_ctx) ) {
                    case 1:
                        {
                        _localctx = new AndExpressionContext(new ExpressionContext(_parentctx, _parentState));
                        ((AndExpressionContext)_localctx).left = _prevctx;
                        pushNewRecursionContext(_localctx, _startState, RULE_expression);
                        setState(16);
                        if (!(precpred(_ctx, 2))) throw new FailedPredicateException(this, "precpred(_ctx, 2)");
                        setState(17);
                        ((AndExpressionContext)_localctx).operator = match(AND);
                        setState(18);
                        ((AndExpressionContext)_localctx).right = expression(3);
                        }
                        break;
                    case 2:
                        {
                        _localctx = new OrExpressionContext(new ExpressionContext(_parentctx, _parentState));
                        ((OrExpressionContext)_localctx).left = _prevctx;
                        pushNewRecursionContext(_localctx, _startState, RULE_expression);
                        setState(19);
                        if (!(precpred(_ctx, 1))) throw new FailedPredicateException(this, "precpred(_ctx, 1)");
                        setState(20);
                        ((OrExpressionContext)_localctx).operator = match(OR);
                        setState(21);
                        ((OrExpressionContext)_localctx).right = expression(2);
                        }
                        break;
                    }
                    }
                }
                setState(26);
                _errHandler.sync(this);
                _alt = getInterpreter().adaptivePredict(_input,2,_ctx);
            }
            }
        }
        catch (RecognitionException re) {
            _localctx.exception = re;
            _errHandler.reportError(this, re);
            _errHandler.recover(this, re);
        }
        finally {
            unrollRecursionContexts(_parentctx);
        }
        return _localctx;
    }

    public boolean sempred(RuleContext _localctx, int ruleIndex, int predIndex) {
        switch (ruleIndex) {
        case 1:
            return expression_sempred((ExpressionContext)_localctx, predIndex);
        }
        return true;
    }
    private boolean expression_sempred(ExpressionContext _localctx, int predIndex) {
        switch (predIndex) {
        case 0:
            return precpred(_ctx, 2);
        case 1:
            return precpred(_ctx, 1);
        }
        return true;
    }

    public static final String _serializedATN =
        "\u0004\u0001\b\u001c\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0001"+
        "\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001"+
        "\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0003\u0001\u000f\b\u0001\u0001"+
        "\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0001\u0005"+
        "\u0001\u0017\b\u0001\n\u0001\f\u0001\u001a\t\u0001\u0001\u0001\u0000\u0001"+
        "\u0002\u0002\u0000\u0002\u0000\u0001\u0001\u0000\u0006\u0007\u001d\u0000"+
        "\u0004\u0001\u0000\u0000\u0000\u0002\u000e\u0001\u0000\u0000\u0000\u0004"+
        "\u0005\u0003\u0002\u0001\u0000\u0005\u0001\u0001\u0000\u0000\u0000\u0006"+
        "\u0007\u0006\u0001\uffff\uffff\u0000\u0007\u000f\u0007\u0000\u0000\u0000"+
        "\b\t\u0005\u0004\u0000\u0000\t\n\u0003\u0002\u0001\u0000\n\u000b\u0005"+
        "\u0005\u0000\u0000\u000b\u000f\u0001\u0000\u0000\u0000\f\r\u0005\u0003"+
        "\u0000\u0000\r\u000f\u0003\u0002\u0001\u0003\u000e\u0006\u0001\u0000\u0000"+
        "\u0000\u000e\b\u0001\u0000\u0000\u0000\u000e\f\u0001\u0000\u0000\u0000"+
        "\u000f\u0018\u0001\u0000\u0000\u0000\u0010\u0011\n\u0002\u0000\u0000\u0011"+
        "\u0012\u0005\u0001\u0000\u0000\u0012\u0017\u0003\u0002\u0001\u0003\u0013"+
        "\u0014\n\u0001\u0000\u0000\u0014\u0015\u0005\u0002\u0000\u0000\u0015\u0017"+
        "\u0003\u0002\u0001\u0002\u0016\u0010\u0001\u0000\u0000\u0000\u0016\u0013"+
        "\u0001\u0000\u0000\u0000\u0017\u001a\u0001\u0000\u0000\u0000\u0018\u0016"+
        "\u0001\u0000\u0000\u0000\u0018\u0019\u0001\u0000\u0000\u0000\u0019\u0003"+
        "\u0001\u0000\u0000\u0000\u001a\u0018\u0001\u0000\u0000\u0000\u0003\u000e"+
        "\u0016\u0018";
    public static final ATN _ATN =
        new ATNDeserializer().deserialize(_serializedATN.toCharArray());
    static {
        _decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
        for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
            _decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
        }
    }
}