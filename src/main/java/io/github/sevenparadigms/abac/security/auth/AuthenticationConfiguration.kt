package io.github.sevenparadigms.abac.security.auth

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
@ConditionalOnProperty("spring.security.secret")
class AuthenticationConfiguration {
    @Bean
    fun userRepository(@Value("\${spring.security.abac.url}") url: String): UserRepository = R2dbcUtils.getRepository(url, UserRepository::class.java)

    @Bean
    fun authenticationManager(
        userDetailsService: ReactiveUserDetailsService,
        passwordEncoder: PasswordEncoder
    ): ReactiveAuthenticationManager = AuthenticationManagerImpl(userDetailsService, passwordEncoder)

    @Bean
    fun reactiveUserDetailsService(userRepository: UserRepository): ReactiveUserDetailsService =
        ReactiveUserDetailsServiceImpl(userRepository)
}