package io.github.sevenparadigms.abac.security.support.config

import io.github.sevenparadigms.abac.Constants.JWT_SECRET_PROPERTY
import io.github.sevenparadigms.abac.configuration.JwtProperties
import io.github.sevenparadigms.abac.security.auth.AuthenticationManagerImpl
import io.github.sevenparadigms.abac.security.auth.ReactiveUserDetailsServiceImpl
import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.auth.encrypt.PBKDF2Encoder
import io.github.sevenparadigms.abac.security.support.ConfigHelper
import org.mockito.Mockito
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.PropertySource
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder

@TestConfiguration
@EnableConfigurationProperties(JwtProperties::class)
@PropertySource("classpath:application.yml", factory = YamlPropertySourceFactory::class)
class AuthConfiguration {

    @Bean
    fun jwtTokenProvider(jwt: JwtProperties): JwtTokenProvider {
        return JwtTokenProvider(jwt)
    }

    @Bean
    fun userRepository(): UserRepository {
        return Mockito.mock(UserRepository::class.java)
    }

    @Bean
    fun passwordEncoder(jwt: JwtProperties): PasswordEncoder {
        return PBKDF2Encoder(jwt)
    }

    @Bean
    fun userDetailsService(): ReactiveUserDetailsService {
        return ReactiveUserDetailsServiceImpl(userRepository())
    }

    @Bean
    fun mockUserDetailsService(): ReactiveUserDetailsService {
        return Mockito.mock(ReactiveUserDetailsService::class.java)
    }

    @Bean
    @ConditionalOnProperty(JWT_SECRET_PROPERTY)
    fun reactiveAuthenticateManager(
        mockUserDetailsService: ReactiveUserDetailsService,
        passwordEncoder: PasswordEncoder
    ): ReactiveAuthenticationManager {
        return AuthenticationManagerImpl(mockUserDetailsService, passwordEncoder)
    }

    @Bean
    fun configHelper(): ConfigHelper {
        return ConfigHelper()
    }
}