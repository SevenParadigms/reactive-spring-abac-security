package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.security.support.config.AuthConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.sevenparadigms.cache.hazelcast.HazelcastCacheConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.data.r2dbc.config.Beans
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ContextConfiguration(classes = [HazelcastCacheConfiguration::class, AuthConfiguration::class])
@ExtendWith(SpringExtension::class)
class JwtTokenProviderTest {

    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider

    @Autowired
    private lateinit var context: ApplicationContext

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
        Assertions.assertEquals(ArrayList<String>(), actual["auth"])
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
        Assertions.assertEquals(listOf("role"), actual["auth"])
        Assertions.assertNotNull(actual["exp"])
    }

    @Test
    fun getAuthentication() {
        Beans.setAndGetContext(context)
        val token = jwtTokenProvider.getAuthToken(authentication)
        val authentication = jwtTokenProvider.getAuthentication(token)
        Assertions.assertTrue(authentication.credentials.toString() == "user")
        Assertions.assertEquals(authentication.authorities.map { it.authority }, listOf("role"))
    }

    private fun createAuthentication(): Authentication {
        val authorities = ArrayList<SimpleGrantedAuthority>()
        authorities.add(SimpleGrantedAuthority("role"))

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