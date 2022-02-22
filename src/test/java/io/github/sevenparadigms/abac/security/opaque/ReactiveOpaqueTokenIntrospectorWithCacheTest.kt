package io.github.sevenparadigms.abac.security.opaque

import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import io.jsonwebtoken.Claims
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class ReactiveOpaqueTokenIntrospectorWithCacheTest {

    @Autowired
    @Qualifier("reactiveOpaqueTokenIntrospector")
    private lateinit var reactiveOpaqueTokenIntrospector: ReactiveOpaqueTokenIntrospector

    @Autowired
    @Qualifier("mockTokenCacheService")
    private lateinit var cacheService: TokenCacheService

    @Test
    fun introspect_whenOk() {
        val cachedToken = this.createCachedToken()
        Mockito.`when`(cacheService.getTokenFromCache(Mockito.anyString())).thenReturn(Mono.just(cachedToken))

        val actual = reactiveOpaqueTokenIntrospector.introspect(getTestToken())

        StepVerifier.create(actual)
            .expectNextCount(1)
            .verifyComplete()
    }

    @Test
    fun introspect_whenTokenIncorrect() {
        val testToken = createCachedToken()
        testToken.status = TokenStatus.INVALID
        Mockito.`when`(cacheService.getTokenFromCache(Mockito.anyString())).thenReturn(Mono.just(testToken))

        val actual = reactiveOpaqueTokenIntrospector.introspect(getTestToken())

        StepVerifier.create(actual)
            .verifyErrorMessage("JWT token status: INVALID")
    }

    @Test
    fun introspect_whenTokenRevoked() {
        val testToken = createCachedToken()
        testToken.status = TokenStatus.REVOKED
        Mockito.`when`(cacheService.getTokenFromCache(Mockito.anyString())).thenReturn(Mono.just(testToken))

        val actual = reactiveOpaqueTokenIntrospector.introspect(getTestToken())

        StepVerifier.create(actual)
            .verifyErrorMessage("JWT token status: REVOKED")
    }

    private fun createCachedToken(): OpaqueTokenPrincipal {
        val attributes: MutableMap<String, Any> = HashMap()
        attributes[Claims.EXPIRATION] = System.currentTimeMillis() + 1000
        attributes[Claims.SUBJECT] = "subj"
        return OpaqueTokenPrincipal(
            status = TokenStatus.SUCCESS,
            attributes = attributes,
            authorities = Collections.emptyList()
        )
    }

    private fun getTestToken(): String {
        return "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0F" +
                "ETUlOLFJPTEVfVVNFUiIsImV4cCI6MTY0MTg5NzkwMn0.bO7g6nOAPzNWq9wXUlOW6mL9cFc1CB63gnEoPtJ8BP2YwadaUW7rwrLrOyj7TcwPzn6RD9ec8ov06cIDJ0hb9A"
    }
}