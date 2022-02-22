package io.github.sevenparadigms.abac.security.abac.service

import io.github.sevenparadigms.abac.security.abac.data.*
import io.github.sevenparadigms.abac.security.context.ExchangeContext
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.runBlocking
import org.sevenparadigms.kotlin.common.debug
import org.springframework.security.access.expression.DenyAllPermissionEvaluator
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Service

@Service
class AbacRulePermissionService(
    private val abacRuleRepository: AbacRuleRepository,
    private val expressionParserCache: ExpressionParserCache,
    private val exchangeContext: ExchangeContext
) : DenyAllPermissionEvaluator() {
    override fun hasPermission(authentication: Authentication, domainObject: Any, action: Any): Boolean {
        debug("Secure user ${authentication.name} action '$action' on object $domainObject")
        val user = authentication.principal as User
        return checkIn(
            AbacSubject(user.username, user.authorities.map { it.authority }.toSet()),
            domainObject,
            action as String
        )
    }

    private fun checkIn(subject: AbacSubject, domainObject: Any, action: String): Boolean {
        var result = false
        runBlocking {
            val context = AbacControlContext(
                subject, domainObject, action, AbacEnvironment(ip = exchangeContext.getRemoteIp(subject.username))
            )
            result = abacRuleRepository.findAllByDomainType(domainObject.javaClass.simpleName)
                .filter { abacRule: AbacRule ->
                    expressionParserCache.parseExpression(abacRule.target).getValue(
                        context,
                        Boolean::class.java
                    )!!
                }
                .any { abacRule: AbacRule ->
                    expressionParserCache.parseExpression(abacRule.condition)
                        .getValue(context, Boolean::class.java)!!
                }
                .awaitFirst()
        }
        return result
    }
}
