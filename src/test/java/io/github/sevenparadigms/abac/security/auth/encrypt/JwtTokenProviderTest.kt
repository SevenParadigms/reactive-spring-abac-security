package io.github.sevenparadigms.abac.security.auth.encrypt

import io.github.sevenparadigms.abac.configuration.JwtProperties
import io.github.sevenparadigms.abac.security.support.config.AbstractTestEnvironment
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.data.r2dbc.support.Beans
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import java.util.*

class JwtTokenProviderTest : AbstractTestEnvironment() {
    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider

    @Autowired
    private lateinit var context: ApplicationContext

    @Autowired
    private lateinit var jwtProperties: JwtProperties

    @Test
    fun getToken() {
        Assertions.assertEquals(jwtProperties.keystorePath, "gateway.p12")
        Assertions.assertNotNull(jwtTokenProvider.getAuthenticationToken(createAuthentication()))
    }

    @Test
    fun getClaims_whenNoAuthorities() {
        val actual = jwtTokenProvider.getAuthenticationTokenClaims(
            jwtTokenProvider.getAuthenticationToken(
                UsernamePasswordAuthenticationToken("user", UUID.randomUUID(), listOf(SimpleGrantedAuthority("role")))
            )
        )
        Assertions.assertEquals("user", actual["sub"])
        Assertions.assertEquals(listOf("role"), actual["roles"])
        Assertions.assertNotNull(actual["exp"])
    }

    @Test
    fun getClaims_whenEmptyToken() {
        Assertions.assertThrows(BadCredentialsException::class.java) { jwtTokenProvider.getAuthenticationTokenClaims("") }
    }

    @Test
    fun getClaims() {
        val actual = jwtTokenProvider.getAuthenticationTokenClaims(jwtTokenProvider.getAuthenticationToken(createAuthentication()))

        Assertions.assertEquals("user", actual["sub"])
        Assertions.assertEquals(listOf("role"), actual["roles"])
        Assertions.assertNotNull(actual["exp"])
    }

    @Test
    fun getAuthentication() {
        val token = jwtTokenProvider.getAuthenticationToken(createAuthentication())
        val authentication = jwtTokenProvider.getAuthentication(token)
        Assertions.assertTrue((authentication.principal as User).username == "user")
        Assertions.assertEquals(authentication.authorities.map { it.authority }.toList(), listOf("role"))
    }

    private fun createAuthentication(): Authentication {
        Beans.setAndGetContext(context)
        return UsernamePasswordAuthenticationToken(
            User(
                "user",
                "",
                listOf(SimpleGrantedAuthority("role"))
            ),
            UUID.randomUUID(),
            listOf(SimpleGrantedAuthority("role"))
        )
    }
}