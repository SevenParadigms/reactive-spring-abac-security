package io.github.sevenparadigms.abac.security.support.config

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.configuration.JwtProperties
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.abac.service.AbacRulePermissionService
import io.github.sevenparadigms.abac.security.context.ExchangeContext
import io.github.sevenparadigms.abac.security.support.model.ServerWebExchangeImpl
import org.mockito.Mockito
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.PropertySource

@TestConfiguration
@EnableConfigurationProperties(JwtProperties::class)
@PropertySource("classpath:application.yml", factory = YamlPropertySourceFactory::class)
class ServiceConfiguration {
    @Bean
    fun abacRuleRepository(): AbacRuleRepository {
        return Mockito.mock(AbacRuleRepository::class.java)
    }

    @Bean
    fun exchangeContext(jwt: JwtProperties): ExchangeContext {
        val exchangeContext = ExchangeContext(jwt)

        val userWebExchange = ServerWebExchangeImpl()
        val guestWebExchange = ServerWebExchangeImpl()

        userWebExchange.attributes[Constants.AUTHORIZE_IP] = "127.0.0.1"
        guestWebExchange.attributes[Constants.AUTHORIZE_IP] = "127.0.0.2"

        exchangeContext.attributes.put("user", userWebExchange)
        exchangeContext.attributes.put("guest", guestWebExchange)
        return exchangeContext
    }

    @Bean
    fun abacRulePermissionService(
        exchangeContext: ExchangeContext,
        abacRuleRepository: AbacRuleRepository
    ): AbacRulePermissionService {
        return AbacRulePermissionService(abacRuleRepository, exchangeContext)
    }

}