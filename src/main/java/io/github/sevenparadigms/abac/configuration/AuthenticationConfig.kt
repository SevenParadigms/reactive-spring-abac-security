package io.github.sevenparadigms.abac.configuration

import io.github.sevenparadigms.abac.Constants.ABAC_URL_PROPERTY
import io.github.sevenparadigms.abac.security.auth.AuthenticationManagerImpl
import io.github.sevenparadigms.abac.security.auth.ReactiveUserDetailsServiceImpl
import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.r2dbc.support.R2dbcUtils
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
@ConditionalOnProperty(ABAC_URL_PROPERTY)
class AuthenticationConfig {
    @Bean
    fun userRepository(@Value("\${$ABAC_URL_PROPERTY}") url: String): UserRepository = R2dbcUtils.getRepository(url, UserRepository::class.java)

    @Bean
    fun authenticationManager(
        userDetailsService: ReactiveUserDetailsService,
        passwordEncoder: PasswordEncoder,
        userRepository: UserRepository
    ): ReactiveAuthenticationManager = AuthenticationManagerImpl(userDetailsService, passwordEncoder, userRepository)

    @Bean
    fun reactiveUserDetailsService(userRepository: UserRepository): ReactiveUserDetailsService =
        ReactiveUserDetailsServiceImpl(userRepository)
}