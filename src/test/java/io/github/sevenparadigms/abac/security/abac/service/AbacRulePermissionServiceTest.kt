package io.github.sevenparadigms.abac.security.abac.service

import io.github.sevenparadigms.abac.security.abac.data.AbacRule
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.support.config.ServiceConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.data.r2dbc.repository.query.Dsl
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.core.publisher.Flux
import java.util.*

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [ServiceConfiguration::class])
class AbacRulePermissionServiceTest {

    @Autowired
    private lateinit var abacRulePermissionService: AbacRulePermissionService

    @Autowired
    private lateinit var abacRuleRepository: AbacRuleRepository

    private val fluxRules: Flux<AbacRule> = createAbacRules()

    @Test
    fun `checkIn when domainObject is Dsl and action is findAll by user WITH authenticated ip`() {
        Mockito.`when`(abacRuleRepository.findAllByDomainType(anyString())).thenReturn(fluxRules)

        val authorities = Collections.singletonList(GrantedAuthority { "USER" })
        val authentication: Authentication =
            UsernamePasswordAuthenticationToken(createUser("user", authorities), "password")
        val dsl = Dsl(null.toString(), 0, 0, "id:desc", null.toString(), null.toString())

        Assertions.assertTrue(abacRulePermissionService.hasPermission(authentication, dsl, "findAll"))
    }

    @Test
    fun `checkIn when domainObject is Dsl and action is findAll by ADMIN with authenticated ip`() {
        Mockito.`when`(abacRuleRepository.findAllByDomainType(anyString())).thenReturn(fluxRules)

        val authorities = Collections.singletonList(GrantedAuthority { "ROLE_ADMIN" })
        val authentication: Authentication =
            UsernamePasswordAuthenticationToken(createUser("user", authorities), "password")
        val dsl = Dsl(null.toString(), 0, 0, "id:desc", null.toString(), null.toString())

        Assertions.assertTrue(abacRulePermissionService.hasPermission(authentication, dsl, "findAll"))
    }

    @Test
    fun `checkIn when domainObject is Dsl and action is findAll by user WITHOUT authenticated ip`() {
        Mockito.`when`(abacRuleRepository.findAllByDomainType(anyString())).thenReturn(fluxRules)

        val authorities = Collections.singletonList(GrantedAuthority { "USER" })
        val authentication: Authentication =
            UsernamePasswordAuthenticationToken(createUser("guest", authorities), "password")
        val dsl = Dsl(null.toString(), 0, 0, "id:desc", null.toString(), null.toString())

        Assertions.assertFalse(abacRulePermissionService.hasPermission(authentication, dsl, "findAll"))
    }

    @Test
    fun `checkIn when domainObject is Dsl and action is findAll by ADMIN without authenticated ip`() {
        Mockito.`when`(abacRuleRepository.findAllByDomainType(anyString())).thenReturn(fluxRules)

        val authorities = Collections.singletonList(GrantedAuthority { "ROLE_ADMIN" })
        val authentication: Authentication =
            UsernamePasswordAuthenticationToken(createUser("guest", authorities), "password")
        val dsl = Dsl(null.toString(), 0, 0, "id:desc", null.toString(), null.toString())

        Assertions.assertTrue(abacRulePermissionService.hasPermission(authentication, dsl, "findAll"))
    }

    private fun createAbacRules(): Flux<AbacRule> {
        val rules: MutableList<AbacRule> = ArrayList()
        val parser = SpelExpressionParser()
        rules.add(
            AbacRule(
                UUID.randomUUID(),
                "rule",
                "Dsl",
                parser.parseExpression("action == 'findAll' and subject.roles.contains('ROLE_ADMIN')"),
                parser.parseExpression("domainObject.sort == 'id:desc'")
            )
        )
        rules.add(
            AbacRule(
                UUID.randomUUID(),
                "ip rule",
                "Dsl",
                parser.parseExpression("action == 'findAll' and environment.ip == '127.0.0.1'"),
                parser.parseExpression("domainObject.sort == 'id:desc'")
            )
        )
        return Flux.fromIterable(rules)
    }

    private fun createUser(login: String, authorities: Collection<GrantedAuthority>): User {
        return User(
            login,
            "password",
            authorities
        )
    }
}