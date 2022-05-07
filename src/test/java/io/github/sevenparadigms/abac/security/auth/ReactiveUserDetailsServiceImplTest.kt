package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import io.github.sevenparadigms.abac.security.support.config.AbstractTestEnvironment
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.util.*

class ReactiveUserDetailsServiceImplTest : AbstractTestEnvironment() {
    @Autowired
    @Qualifier("userDetailsService")
    private lateinit var userDetailsService: ReactiveUserDetailsService

    @Autowired
    private lateinit var userRepository: UserRepository

    @Test
    fun findByUsername_whenUserExist(){
        Mockito.`when`(userRepository.findByLogin(anyString())).thenReturn(Mono.just(createUserPrincipal()))

        StepVerifier.create(userDetailsService.findByUsername("user"))
            .expectNextCount(1)
            .thenCancel()
            .verify()
    }

    @Test
    fun findByUsername_whenUserNotExist(){
        Mockito.`when`(userRepository.findByLogin(anyString())).thenReturn(Mono.empty())

        StepVerifier.create(userDetailsService.findByUsername("user"))
            .expectNextCount(0)
            .thenCancel()
            .verify()
    }

    private fun createUserPrincipal(): UserPrincipal {
        return UserPrincipal(
            UUID.randomUUID(),
            "user",
            "password",
            listOf("ROLE_USER")
        )
    }
}