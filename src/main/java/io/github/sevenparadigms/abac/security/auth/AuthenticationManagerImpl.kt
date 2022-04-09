package io.github.sevenparadigms.abac.security.auth

import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import reactor.core.publisher.Mono

class AuthenticationManagerImpl(
    private val userDetailsService: ReactiveUserDetailsService,
    private val passwordEncoder: PasswordEncoder
) : ReactiveAuthenticationManager {
    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        return if (authentication.isAuthenticated) {
            Mono.just(authentication)
        } else Mono.just(authentication)
            .cast(UsernamePasswordAuthenticationToken::class.java)
            .flatMap { userDetailsService.findByUsername(it.name) }
            .filter { passwordEncoder.matches(authentication.credentials as String, it.password) }
            .switchIfEmpty(Mono.error { BadCredentialsException("Invalid credentials") })
            .map { UsernamePasswordAuthenticationToken(it, null, it.authorities) }
    }
}