package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import reactor.core.publisher.Mono

class ReactiveUserDetailsServiceImpl(private val userRepository: UserRepository) : ReactiveUserDetailsService {
    override fun findByUsername(login: String): Mono<UserDetails> {
        return userRepository.findByLogin(login)
            .flatMap { userPrincipal ->
                val grantedAuthorities = userPrincipal.authorities!!.map { SimpleGrantedAuthority(it) }.toList()
                Mono.just(User(userPrincipal.login, userPrincipal.password, grantedAuthorities) as UserDetails)
            }
    }
}