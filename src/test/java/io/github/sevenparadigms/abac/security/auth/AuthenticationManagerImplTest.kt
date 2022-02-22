package io.github.sevenparadigms.abac.security.auth


import io.github.sevenparadigms.abac.security.support.config.AuthConfiguration
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import kotlin.collections.ArrayList

@ContextConfiguration(classes = [AuthConfiguration::class])
@ExtendWith(SpringExtension::class)
class AuthenticationManagerImplTest {

    @Autowired
    private lateinit var authenticationManagerImpl: ReactiveAuthenticationManager

    @Autowired
    @Qualifier("mockUserDetailsService")
    private lateinit var mockUserDetailsService: ReactiveUserDetailsService

    @Test
    fun authenticate_whenCorrectCredentials() {
        val authentication = createAuthentication()
        authentication.isAuthenticated = false
        Mockito.`when`(mockUserDetailsService.findByUsername(anyString())).thenReturn(createUserDetails())

        val authenticate = authenticationManagerImpl.authenticate(authentication)

        StepVerifier.create(authenticate)
            .expectNextCount(1)
            .thenCancel()
            .verify()
    }

    @Test
    fun authenticate_whenAuthenticated() {
        val authentication = createAuthentication()
        Mockito.`when`(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.empty())

        val authenticate = authenticationManagerImpl.authenticate(authentication)

        StepVerifier.create(authenticate)
            .expectNextCount(1)
            .thenCancel()
            .verify()
    }

    @Test
    fun authenticate_whenNotCorrectCredentials() {
        val authentication = createAuthentication()
        authentication.isAuthenticated = false
        Mockito.`when`(mockUserDetailsService.findByUsername(anyString())).thenReturn(Mono.empty())

        val authenticate = authenticationManagerImpl.authenticate(authentication)

        StepVerifier.create(authenticate)
            .verifyError(BadCredentialsException::class.java)
    }

    private fun createAuthentication(): Authentication {
        val authorities = ArrayList<SimpleGrantedAuthority>()
        authorities.add(SimpleGrantedAuthority("USER"))

        return UsernamePasswordAuthenticationToken(createUser(authorities), "password", authorities)
    }

    private fun createUser(authorities: List<SimpleGrantedAuthority>): User {
        return User(
            "user",
            "",
            authorities
        )
    }

    private fun createUserDetails(): Mono<UserDetails> {
        val authorities = ArrayList<SimpleGrantedAuthority>()
        authorities.add(SimpleGrantedAuthority("USER"))

        return Mono.just(User("user", "7jSU1K/qEiKHmpnCSNA8t8iz3wSPEw==", authorities) as UserDetails)
    }

}