package io.github.sevenparadigms.abac.security.abac.service

import io.github.sevenparadigms.abac.Constants.ABAC_URL_PROPERTY
import io.github.sevenparadigms.abac.security.abac.data.AbacControlContext
import io.github.sevenparadigms.abac.security.abac.data.AbacEnvironment
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.abac.data.AbacSubject
import io.github.sevenparadigms.abac.security.context.ExchangeContext
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.runBlocking
import org.sevenparadigms.kotlin.common.debug
import org.sevenparadigms.kotlin.common.objectToJson
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.access.expression.DenyAllPermissionEvaluator
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Service

@Service
@ConditionalOnProperty(ABAC_URL_PROPERTY)
class AbacRulePermissionService(
    private val abacRuleRepository: AbacRuleRepository,
    private val exchangeContext: ExchangeContext
) : DenyAllPermissionEvaluator() {
    override fun hasPermission(authentication: Authentication, domainObject: Any, action: Any): Boolean {
        debug("Check user ${authentication.name} action '$action' on object ${domainObject.objectToJson()}")
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
                .filter { it.target.getValue(context, Boolean::class.java)!! }
                .any { it.condition.getValue(context, Boolean::class.java)!! }
                .awaitFirst()
        }
        return result
    }
}
