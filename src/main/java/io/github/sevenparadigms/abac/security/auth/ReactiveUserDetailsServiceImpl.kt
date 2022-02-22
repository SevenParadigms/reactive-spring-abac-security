package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.auth.data.Authority
import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import org.sevenparadigms.kotlin.common.jsonToObjectList
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import reactor.core.publisher.Mono
import java.util.stream.Collectors

class ReactiveUserDetailsServiceImpl(private val userRepository: UserRepository) : ReactiveUserDetailsService {
    override fun findByUsername(login: String): Mono<UserDetails> {
        return userRepository.findByLogin(login)
            .flatMap {
                val grantedAuthorities = it.authorities!!.jsonToObjectList(Authority::class.java).stream()
                    .map { (_, name): Authority -> SimpleGrantedAuthority(name) }
                    .collect(Collectors.toList())
                Mono.just(User(it.login, it.password, grantedAuthorities) as UserDetails)
            }
    }
}