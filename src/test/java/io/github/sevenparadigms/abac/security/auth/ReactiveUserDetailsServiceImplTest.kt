package io.github.sevenparadigms.abac.security.auth

import io.github.sevenparadigms.abac.security.auth.data.UserPrincipal
import io.github.sevenparadigms.abac.security.auth.data.UserRepository
import io.github.sevenparadigms.abac.security.support.config.AuthConfiguration
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.sevenparadigms.kotlin.common.objectToJson
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.util.*

@ContextConfiguration(classes = [AuthConfiguration::class])
@ExtendWith(SpringExtension::class)
class ReactiveUserDetailsServiceImplTest {

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
            "[{\"id\":\"8754c717-5661-11ec-b49d-73780888af27\",\"name\":\"ROLE_USER\"}]".objectToJson()
        )
    }
}