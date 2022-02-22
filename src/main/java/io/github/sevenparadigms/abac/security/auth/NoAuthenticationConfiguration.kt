package io.github.sevenparadigms.abac.security.auth

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.security.authentication.ReactiveAuthenticationManager

@Configuration
@ConditionalOnProperty("spring.security.public")
class NoAuthenticationConfiguration {
    @Bean
    @Primary
    fun authenticationManager(): ReactiveAuthenticationManager = NoAuthenticationManagerImpl()
}