package io.github.sevenparadigms.abac.security.support.config

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.abac.service.AbacRulePermissionService
import io.github.sevenparadigms.abac.security.abac.service.ExpressionParserCache
import io.github.sevenparadigms.abac.security.support.model.ServerWebExchangeImpl
import io.github.sevenparadigms.abac.security.context.ExchangeContext
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.PropertySource

@TestConfiguration
@PropertySource("classpath:application.yml", factory = YamlPropertySourceFactory::class)
class ServiceConfiguration {

    @Bean
    fun expressionParserCache(): ExpressionParserCache {
        return ExpressionParserCache()
    }

    @Bean
    fun abacRuleRepository(): AbacRuleRepository {
        return Mockito.mock(AbacRuleRepository::class.java)
    }

    @Bean
    fun exchangeContext(
        @Value("\${spring.security.expiration}") expiration: String
    ): ExchangeContext {
        val exchangeContext = ExchangeContext(expiration)

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
        abacRuleRepository: AbacRuleRepository,
        expressionParserCache: ExpressionParserCache
    ): AbacRulePermissionService {
        return AbacRulePermissionService(abacRuleRepository, expressionParserCache, exchangeContext)
    }

}