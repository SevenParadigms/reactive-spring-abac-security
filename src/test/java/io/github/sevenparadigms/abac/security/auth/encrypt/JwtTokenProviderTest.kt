package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.security.support.config.AuthConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.internal.matchers.apachecommons.ReflectionEquals
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ContextConfiguration(classes = [AuthConfiguration::class])
@ExtendWith(SpringExtension::class)
class JwtTokenProviderTest {

    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider
    private val authentication = createAuthentication()

    @Test
    fun getToken() {
        Assertions.assertNotNull(jwtTokenProvider.getAuthToken(authentication))
    }

    @Test
    fun getClaims_whenNoAuthorities() {
        val actual = jwtTokenProvider.getClaims(
            jwtTokenProvider.getAuthToken(
                UsernamePasswordAuthenticationToken("user", "password")
            )
        )
        Assertions.assertEquals("user", actual["sub"])
        Assertions.assertEquals(ArrayList<String>(), actual["roles"])
        Assertions.assertNotNull(actual["exp"])
    }

    @Test
    fun getClaims_whenEmptyToken() {
        Assertions.assertThrows(BadCredentialsException::class.java) { jwtTokenProvider.getClaims("") }
    }

    @Test
    fun getClaims() {
        val actual = jwtTokenProvider.getClaims(jwtTokenProvider.getAuthToken(authentication))

        Assertions.assertEquals("user", actual["sub"])
        Assertions.assertEquals(listOf("USER"), actual["roles"])
        Assertions.assertNotNull(actual["exp"])
    }

    @Test
    fun getAuthentication() {
        val token = jwtTokenProvider.getAuthToken(authentication)
        Assertions.assertTrue(
            ReflectionEquals(
                authentication,
                "credentials"
            ).matches(jwtTokenProvider.getAuthentication(token))
        )
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
}