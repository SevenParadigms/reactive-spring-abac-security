package io.github.sevenparadigms.abac.security.support.config

import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.opaque.ReactiveOpaqueTokenIntrospectorImpl
import io.github.sevenparadigms.abac.security.opaque.encrypt.OpaqueTokenValidator
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.github.sevenparadigms.abac.security.opaque.service.TokenIntrospectionService
import io.github.sevenparadigms.abac.security.opaque.service.impl.TokenAuthorizationServiceImpl
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.PropertySource
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector

@Configuration
@PropertySource("classpath:application.yml", factory = YamlPropertySourceFactory::class)
class CacheDisabledConfig {

    @Bean("validator")
    fun validator(
        @Value("\${spring.security.jwt.introspection.secret:default}") secret: String,
    ): OpaqueTokenValidator {
        return OpaqueTokenValidator("1800", secret)
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
    fun mockIntrospector(): TokenIntrospectionService? {
        return Mockito.mock(TokenIntrospectionService::class.java)
    }

    @Bean
    fun reactiveOpaqueTokenIntrospector(
        @Qualifier("mockIntrospector") mockIntospector: TokenIntrospectionService
    ): ReactiveOpaqueTokenIntrospector {
        return ReactiveOpaqueTokenIntrospectorImpl(null, mockIntospector)
    }
}