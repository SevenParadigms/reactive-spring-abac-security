package io.github.sevenparadigms.abac.configuration

import io.github.sevenparadigms.abac.security.cache.TokenCacheManager
import io.github.sevenparadigms.abac.security.cache.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.cache.listener.EventListenerImpl
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.cache.service.impl.TokenCacheServiceImpl
import io.github.sevenparadigms.abac.security.opaque.ReactiveOpaqueTokenIntrospectorImpl
import io.github.sevenparadigms.abac.security.opaque.encrypt.OpaqueTokenValidator
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.github.sevenparadigms.abac.security.opaque.service.TokenIntrospectionService
import io.github.sevenparadigms.abac.security.opaque.service.impl.TokenAuthorizationServiceImpl
import io.github.sevenparadigms.abac.security.opaque.service.impl.TokenIntrospectionServiceImpl
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.AllNestedConditions
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.cache.CacheManager
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.ConfigurationCondition
import org.springframework.data.r2dbc.config.Beans
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import java.time.Duration

@Configuration
class OpaqueConfig : AllNestedConditions(ConfigurationCondition.ConfigurationPhase.PARSE_CONFIGURATION) {

    @Bean
    @ConditionalOnMissingBean(value = [ApplicationListener::class],
        parameterizedContainer = [RevokeTokenEvent::class])
    @ConditionalOnProperty(name = ["spring.security.introspection.secret"])
    fun eventListener(
        cacheService: TokenCacheService,
    ): ApplicationListener<RevokeTokenEvent> {
        return EventListenerImpl(cacheService = cacheService)
    }

    @Bean
    @ConditionalOnProperty(name = ["spring.security.introspection.secret"])
    fun opaqueTokenValidator(
        @Value("\${spring.security.introspection.secret:}") secret: String,
        @Value("\${spring.security.expiration:1800}") expiration: String,
    ): OpaqueTokenValidator {
        return OpaqueTokenValidator(expiration = expiration, secret = secret)
    }

    @Bean
    @ConditionalOnMissingBean(type = ["CacheManager"])
    @ConditionalOnProperty(name = ["spring.security.introspection.cache-token"], havingValue = "true")
    fun cacheManager(@Value("\${spring.security.expiration:1800}") expiration: String): CacheManager {
        return TokenCacheManager(expiration = expiration)
    }

    @Bean
    @ConditionalOnBean(CacheManager::class)
    @ConditionalOnProperty(name = ["spring.security.introspection.cache-token"], havingValue = "true")
    fun tokenCacheService(
        validator: OpaqueTokenValidator,
        cacheManager: CacheManager,
    ): TokenCacheServiceImpl {
        return TokenCacheServiceImpl(cacheManager = cacheManager, validator = validator)
    }

    @Bean
    @ConditionalOnMissingBean(type = ["TokenAuthorizationService"])
    @ConditionalOnProperty(name = ["spring.security.introspection.uri"])
    fun tokenAuthorizationService(
        validator: OpaqueTokenValidator,
    ): TokenAuthorizationService {
        return TokenAuthorizationServiceImpl(validator = validator)
    }

    @Bean
    @ConditionalOnProperty(name = ["spring.security.introspection.secret"])
    fun reactiveOpaqueTokenIntrospector(
        @Value("\${spring.security.introspection.uri:}") introspectionUrl: String,
        @Value("\${spring.security.introspection.secret:}") introspectionSecret: String,
        @Value("\${spring.security.introspection.client-id:}") introspectionClientId: String,
        @Value("\${spring.security.introspection.response-timeout:60}") responseTimeout: String,
    ): ReactiveOpaqueTokenIntrospector {
        var cacheService: TokenCacheServiceImpl? = null
        try {
            cacheService = Beans.of(TokenCacheServiceImpl::class.java)
        } catch (_: Exception) { }

        return ReactiveOpaqueTokenIntrospectorImpl(
            cacheService = cacheService,
            delegate = this.introspectionService(
                introspectionUrl = introspectionUrl,
                introspectionSecret = introspectionSecret,
                introspectionClientId = introspectionClientId,
                responseTimeout = responseTimeout
            )
        )

    }

    private fun webClient(responseTimeout: Long): WebClient {
        return WebClient.builder()
            .clientConnector(
                ReactorClientHttpConnector(
                    HttpClient.create()
                        .followRedirect(true)
                        .responseTimeout(Duration.ofSeconds(responseTimeout))
                )
            ).build()
    }

    private fun introspectionService(
        introspectionUrl: String,
        introspectionSecret: String,
        introspectionClientId: String,
        responseTimeout: String,
    ): TokenIntrospectionService? {
        if (introspectionUrl.isNotEmpty()) {
            return if (introspectionClientId.isEmpty()) {
                TokenIntrospectionServiceImpl(
                    introspectionUrl = introspectionUrl,
                    webClient = this.webClient(responseTimeout.toLong())
                )
            } else TokenIntrospectionServiceImpl(
                introspectionUrl = introspectionUrl,
                introspectionClientId = introspectionClientId,
                introspectionSecret = introspectionSecret
            )
        }
        return null
    }
}