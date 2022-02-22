package io.github.sevenparadigms.abac.security.support.config

import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.cache.TokenCacheManager
import io.github.sevenparadigms.abac.security.cache.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.cache.listener.EventListenerImpl
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.cache.service.impl.TokenCacheServiceImpl
import io.github.sevenparadigms.abac.security.opaque.ReactiveOpaqueTokenIntrospectorImpl
import io.github.sevenparadigms.abac.security.opaque.encrypt.OpaqueTokenValidator
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.github.sevenparadigms.abac.security.opaque.service.impl.TokenAuthorizationServiceImpl
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.cache.CacheManager
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.DependsOn
import org.springframework.context.annotation.PropertySource
import org.springframework.context.event.ApplicationEventMulticaster
import org.springframework.context.event.SimpleApplicationEventMulticaster
import org.springframework.core.task.SimpleAsyncTaskExecutor
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector


@TestConfiguration
@PropertySource("classpath:application.yml", factory = YamlPropertySourceFactory::class)
class OpaqueCacheConfiguration {

    @Bean("validator")
    fun validator(
        @Value("\${spring.security.introspection.secret}") secret: String,
    ): OpaqueTokenValidator {
        return OpaqueTokenValidator("1800", secret)
    }

    @Bean
    @DependsOn("validator")
    fun tokenCacheManager(): CacheManager {
        return TokenCacheManager("1800")
    }

    @Bean
    fun tokenCacheService(
        validator: OpaqueTokenValidator,
    ): TokenCacheService {
        return TokenCacheServiceImpl(cacheManager = tokenCacheManager(), validator = validator)
    }

    @Bean
    fun mockTokenCacheService(): TokenCacheService {
        return Mockito.mock(TokenCacheService::class.java)
    }

    @Bean
    fun jwtTokenProvider(): JwtTokenProvider {
        return JwtTokenProvider()
    }

    @Bean
    fun authorizationService(
        validator: OpaqueTokenValidator,
    ): TokenAuthorizationService {
        return TokenAuthorizationServiceImpl(validator = validator)
    }

    @Bean
    fun reactiveOpaqueTokenIntrospector(
        @Qualifier("mockTokenCacheService") cacheService: TokenCacheService,
    ): ReactiveOpaqueTokenIntrospector {
        return ReactiveOpaqueTokenIntrospectorImpl(cacheService, null)
    }

    @Bean
    fun eventListener(
        @Qualifier("mockTokenCacheService") cacheService: TokenCacheService,
    ): ApplicationListener<RevokeTokenEvent> {
        return EventListenerImpl(cacheService = cacheService)
    }

    @Bean(name = ["applicationEventMulticaster"])
    fun eventMulticaster(): ApplicationEventMulticaster? {
        val eventMulticaster = SimpleApplicationEventMulticaster()
        eventMulticaster.setTaskExecutor(SimpleAsyncTaskExecutor())
        return eventMulticaster
    }
}