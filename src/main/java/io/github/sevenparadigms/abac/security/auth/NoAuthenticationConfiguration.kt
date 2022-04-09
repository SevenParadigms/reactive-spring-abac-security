package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.Constants.JWT_PUBLIC_PROPERTY
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.authentication.ReactiveAuthenticationManager

@Configuration
@ConditionalOnProperty(JWT_PUBLIC_PROPERTY)
class NoAuthenticationConfiguration {
    @Bean
    @Primary
    fun authenticationManager(): ReactiveAuthenticationManager = NoAuthenticationManagerImpl()
}