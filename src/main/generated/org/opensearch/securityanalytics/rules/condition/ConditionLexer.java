// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenStream;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.misc.*;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class ConditionLexer extends Lexer {
    static { RuntimeMetaData.checkVersion("4.11.1", RuntimeMetaData.VERSION); }

    protected static final DFA[] _decisionToDFA;
    protected static final PredictionContextCache _sharedContextCache =
        new PredictionContextCache();
    public static final int
        AND=1, OR=2, NOT=3, LPAREN=4, RPAREN=5, SELECTOR=6, IDENTIFIER=7, WHITESPACE=8;
    public static String[] channelNames = {
        "DEFAULT_TOKEN_CHANNEL", "HIDDEN"
    };

    public static String[] modeNames = {
        "DEFAULT_MODE"
    };

    private static String[] makeRuleNames() {
        return new String[] {
            "AND", "OR", "NOT", "LPAREN", "RPAREN", "SELECTOR", "IDENTIFIER", "WHITESPACE"
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


    public ConditionLexer(CharStream input) {
        super(input);
        _interp = new LexerATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
    }

    @Override
    public String getGrammarFileName() { return "Condition.g4"; }

    @Override
    public String[] getRuleNames() { return ruleNames; }

    @Override
    public String getSerializedATN() { return _serializedATN; }

    @Override
    public String[] getChannelNames() { return channelNames; }

    @Override
    public String[] getModeNames() { return modeNames; }

    @Override
    public ATN getATN() { return _ATN; }

    public static final String _serializedATN =
        "\u0004\u0000\bA\u0006\uffff\uffff\u0002\u0000\u0007\u0000\u0002\u0001"+
        "\u0007\u0001\u0002\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004"+
        "\u0007\u0004\u0002\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007"+
        "\u0007\u0007\u0001\u0000\u0001\u0000\u0001\u0000\u0001\u0000\u0001\u0001"+
        "\u0001\u0001\u0001\u0001\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002"+
        "\u0001\u0003\u0001\u0003\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005"+
        "\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0003\u0005"+
        "(\b\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005"+
        "\u0001\u0005\u0004\u00050\b\u0005\u000b\u0005\f\u00051\u0001\u0006\u0001"+
        "\u0006\u0005\u00066\b\u0006\n\u0006\f\u00069\t\u0006\u0001\u0007\u0004"+
        "\u0007<\b\u0007\u000b\u0007\f\u0007=\u0001\u0007\u0001\u0007\u0000\u0000"+
        "\b\u0001\u0001\u0003\u0002\u0005\u0003\u0007\u0004\t\u0005\u000b\u0006"+
        "\r\u0007\u000f\b\u0001\u0000\u0004\u0005\u0000**09AZ__az\u0003\u0000A"+
        "Z__az\u0004\u000009AZ__az\u0003\u0000\t\n\r\r  E\u0000\u0001\u0001\u0000"+
        "\u0000\u0000\u0000\u0003\u0001\u0000\u0000\u0000\u0000\u0005\u0001\u0000"+
        "\u0000\u0000\u0000\u0007\u0001\u0000\u0000\u0000\u0000\t\u0001\u0000\u0000"+
        "\u0000\u0000\u000b\u0001\u0000\u0000\u0000\u0000\r\u0001\u0000\u0000\u0000"+
        "\u0000\u000f\u0001\u0000\u0000\u0000\u0001\u0011\u0001\u0000\u0000\u0000"+
        "\u0003\u0015\u0001\u0000\u0000\u0000\u0005\u0018\u0001\u0000\u0000\u0000"+
        "\u0007\u001c\u0001\u0000\u0000\u0000\t\u001e\u0001\u0000\u0000\u0000\u000b"+
        "\'\u0001\u0000\u0000\u0000\r3\u0001\u0000\u0000\u0000\u000f;\u0001\u0000"+
        "\u0000\u0000\u0011\u0012\u0005a\u0000\u0000\u0012\u0013\u0005n\u0000\u0000"+
        "\u0013\u0014\u0005d\u0000\u0000\u0014\u0002\u0001\u0000\u0000\u0000\u0015"+
        "\u0016\u0005o\u0000\u0000\u0016\u0017\u0005r\u0000\u0000\u0017\u0004\u0001"+
        "\u0000\u0000\u0000\u0018\u0019\u0005n\u0000\u0000\u0019\u001a\u0005o\u0000"+
        "\u0000\u001a\u001b\u0005t\u0000\u0000\u001b\u0006\u0001\u0000\u0000\u0000"+
        "\u001c\u001d\u0005(\u0000\u0000\u001d\b\u0001\u0000\u0000\u0000\u001e"+
        "\u001f\u0005)\u0000\u0000\u001f\n\u0001\u0000\u0000\u0000 (\u00051\u0000"+
        "\u0000!\"\u0005a\u0000\u0000\"#\u0005n\u0000\u0000#(\u0005y\u0000\u0000"+
        "$%\u0005a\u0000\u0000%&\u0005l\u0000\u0000&(\u0005l\u0000\u0000\' \u0001"+
        "\u0000\u0000\u0000\'!\u0001\u0000\u0000\u0000\'$\u0001\u0000\u0000\u0000"+
        "()\u0001\u0000\u0000\u0000)*\u0005 \u0000\u0000*+\u0005o\u0000\u0000+"+
        ",\u0005f\u0000\u0000,-\u0005 \u0000\u0000-/\u0001\u0000\u0000\u0000.0"+
        "\u0007\u0000\u0000\u0000/.\u0001\u0000\u0000\u000001\u0001\u0000\u0000"+
        "\u00001/\u0001\u0000\u0000\u000012\u0001\u0000\u0000\u00002\f\u0001\u0000"+
        "\u0000\u000037\u0007\u0001\u0000\u000046\u0007\u0002\u0000\u000054\u0001"+
        "\u0000\u0000\u000069\u0001\u0000\u0000\u000075\u0001\u0000\u0000\u0000"+
        "78\u0001\u0000\u0000\u00008\u000e\u0001\u0000\u0000\u000097\u0001\u0000"+
        "\u0000\u0000:<\u0007\u0003\u0000\u0000;:\u0001\u0000\u0000\u0000<=\u0001"+
        "\u0000\u0000\u0000=;\u0001\u0000\u0000\u0000=>\u0001\u0000\u0000\u0000"+
        ">?\u0001\u0000\u0000\u0000?@\u0006\u0007\u0000\u0000@\u0010\u0001\u0000"+
        "\u0000\u0000\u0005\u0000\'17=\u0001\u0006\u0000\u0000";
    public static final ATN _ATN =
        new ATNDeserializer().deserialize(_serializedATN.toCharArray());
    static {
        _decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
        for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
            _decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
        }
    }
}