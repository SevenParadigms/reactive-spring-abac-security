package io.github.sevenparadigms.abac.security.abac.service

import org.springframework.expression.Expression
import org.springframework.expression.ExpressionParser
import org.springframework.expression.ParseException
import org.springframework.expression.ParserContext
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentHashMap

@Component
class ExpressionParserCache : ExpressionParser {
    private val cache: MutableMap<String, Expression> = ConcurrentHashMap(720)
    private val parser: ExpressionParser = SpelExpressionParser()

    @Throws(ParseException::class)
    override fun parseExpression(expressionString: String): Expression {
        return cache.computeIfAbsent(expressionString) {
            parser.parseExpression(it)
        }
    }

    @Throws(ParseException::class)
    override fun parseExpression(expressionString: String, context: ParserContext): Expression {
        throw UnsupportedOperationException("Parsing using ParserContext is not supported")
    }
}