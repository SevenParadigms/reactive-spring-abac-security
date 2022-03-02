package io.github.sevenparadigms.abac.security.cache.service

import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.cache.service.impl.TokenCacheServiceImpl
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import io.jsonwebtoken.Claims
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.test.StepVerifier
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class TokenCacheServiceTest {

    @Autowired
    @Qualifier("tokenCacheService")
    private lateinit var cacheService: TokenCacheServiceImpl

    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider

    private lateinit var opaqueTokenPrincipal: OpaqueTokenPrincipal
    private lateinit var expiredToken: String
    private lateinit var invalidToken: String
    private lateinit var correctToken: String

    @BeforeAll
    fun setup() {
        opaqueTokenPrincipal = this.createCachedToken()
        expiredToken = this.getTestExpiredToken()
        invalidToken = expiredToken.dropLast(10)
        correctToken = jwtTokenProvider.getAuthToken(UsernamePasswordAuthenticationToken(
            null, null, Collections.emptyList()
        ))
    }

    @Test
    fun putInCache_whenSuccess() {
        val correctToken = jwtTokenProvider.getAuthToken(UsernamePasswordAuthenticationToken(
            null, null, Collections.emptyList()
        ))
        val actual = cacheService.putInCache(correctToken, opaqueTokenPrincipal)

        StepVerifier.create(actual)
            .expectNextCount(1)
            .verifyComplete()
    }

    @Test
    fun putInCache_whenExpired() {
        val actual = cacheService.putInCache(expiredToken, opaqueTokenPrincipal)

        StepVerifier.create(actual)
            .expectNextCount(1)
            .verifyComplete()
    }

    @Test
    fun putInCache_whenInvalid() {
        val actual = cacheService.putInCache(invalidToken, opaqueTokenPrincipal)
        StepVerifier.create(actual)
            .expectNextCount(1)
            .verifyComplete()
    }

    // token with SUCCESS must have expiration time
    @Test
    fun `putInCache_whenAttributesIsNull and statusSuccess`() {
        val opaqueTokenPrincipalWithoutAttr = OpaqueTokenPrincipal(
            status = TokenStatus.SUCCESS
        )
        cacheService.putInCache(invalidToken, opaqueTokenPrincipalWithoutAttr).block()
        val actual = cacheService.getTokenFromCache(invalidToken)

        StepVerifier.create(actual)
            .verifyError(NullPointerException::class.java)
    }

    @Test
    fun getTokenFromCache_whenOk() {
        cacheService.putInCache(correctToken, opaqueTokenPrincipal).block()
        val actual = cacheService.getTokenFromCache(correctToken)

        StepVerifier.create(actual)
            .expectNext(opaqueTokenPrincipal)
            .verifyComplete()
    }

    @Test
    fun getTokenFromCache_whenRevoked() {
        val revokedToken = this.createCachedToken()
        revokedToken.status = TokenStatus.REVOKED

        cacheService.putInCache(correctToken, revokedToken).block()
        val actual = cacheService.getTokenFromCache(correctToken)

        StepVerifier.create(actual)
            .expectNextMatches { it.status == TokenStatus.REVOKED }
            .verifyComplete()
    }

    @Test
    fun getTokenFromCache_whenExpired() {
        val expiredToken = this.createCachedToken()
        expiredToken.status = TokenStatus.EXPIRED

        cacheService.putInCache(correctToken, expiredToken).block()
        val actual = cacheService.getTokenFromCache(correctToken)

        StepVerifier.create(actual)
            .expectNextMatches { it.status == TokenStatus.EXPIRED }
            .verifyComplete()
    }

    @Test
    fun getTokenFromCache_whenInvalid() {
        val invalidToken = this.createCachedToken()
        invalidToken.status = TokenStatus.INVALID

        cacheService.putInCache(correctToken, invalidToken).block()
        val actual = cacheService.getTokenFromCache(correctToken)

        StepVerifier.create(actual)
            .expectNextMatches { it.status == TokenStatus.INVALID }
            .verifyComplete()
    }

    @Test
    fun getTokenFromCache_whenNotExists() {
        val actual = cacheService.getTokenFromCache(correctToken + 1)

        StepVerifier.create(actual)
            .verifyErrorMessage("Token must be in the cache")
    }

    @Test
    fun revokeToken_whenOk() {
        val revokedToken = jwtTokenProvider.getAuthToken(UsernamePasswordAuthenticationToken(
            null, null, Collections.emptyList()
        ))
        val revokeToken = createCachedToken()

        cacheService.putInCache(revokedToken, revokeToken).block()
        cacheService.revokeSyncToken(revokedToken)
        val actual = cacheService.getTokenFromCache(revokedToken)

        StepVerifier.create(actual)
            .expectNextMatches { it.status == TokenStatus.REVOKED }
            .verifyComplete()
    }

    private fun createCachedToken(): OpaqueTokenPrincipal {
        val attributes: MutableMap<String, Any> = HashMap()
        attributes[Claims.EXPIRATION] = System.currentTimeMillis() + 1000
        return OpaqueTokenPrincipal(
            status = TokenStatus.SUCCESS,
            attributes = attributes,
            authorities = Collections.emptyList()
        )
    }

    private fun getTestExpiredToken(): String {
        return "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTY0MjA2NTg0Nn0." +
                "LEjnN4ehFFb_nm7j3xXX34PhKiN-jihPOmBYvc7pGPKk5rb4mx7nNlCInoVoopXQQkb12NK1aiJdjLYSC_RgSw"
    }
}