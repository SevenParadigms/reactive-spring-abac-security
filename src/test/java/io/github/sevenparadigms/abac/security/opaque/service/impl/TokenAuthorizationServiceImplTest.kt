package io.github.sevenparadigms.abac.security.opaque.service.impl

import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionRequest
import io.github.sevenparadigms.abac.security.opaque.data.TokenIntrospectionSuccessResponse
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.opaque.service.TokenAuthorizationService
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import reactor.test.StepVerifier

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class TokenAuthorizationServiceImplTest {

    @Autowired
    private lateinit var tokenAuthorizationService: TokenAuthorizationService

    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider

    @Test
    fun `validateToken valid token`() {
        val authorities = ArrayList<SimpleGrantedAuthority>()
        authorities.add(SimpleGrantedAuthority("USER"))

        val correctToken = jwtTokenProvider.getToken(UsernamePasswordAuthenticationToken(
            this.createUser(authorities), "pass", authorities
        ))
        val response = tokenAuthorizationService.validateToken(TokenIntrospectionRequest(correctToken))

        StepVerifier.create(response)
            .expectNextMatches {
                it as TokenIntrospectionSuccessResponse
                it.status == TokenStatus.SUCCESS && it.expiration != null && it.authorities != null
            }
            .verifyComplete()

        StepVerifier.create(response)
    }

    @Test
    fun `validateToken expired token`() {
        val response = tokenAuthorizationService.validateToken(
            TokenIntrospectionRequest(this.getTestExpiredToken())
        )

        StepVerifier.create(response)
            .expectNextMatches { (it as TokenIntrospectionSuccessResponse).status == TokenStatus.EXPIRED }
            .verifyComplete()

        StepVerifier.create(response)
    }

    @Test
    fun `validateToken invalid token`() {
        val response = tokenAuthorizationService.validateToken(
            TokenIntrospectionRequest("123123123")
        )

        StepVerifier.create(response)
            .expectNextMatches { (it as TokenIntrospectionSuccessResponse).status == TokenStatus.INVALID }
            .verifyComplete()
    }


    private fun createUser(authorities: List<SimpleGrantedAuthority>): User {
        return User(
            "user",
            "",
            authorities
        )
    }

    private fun getTestExpiredToken(): String {
        return "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTY0MjA2NTg0Nn0." +
                "LEjnN4ehFFb_nm7j3xXX34PhKiN-jihPOmBYvc7pGPKk5rb4mx7nNlCInoVoopXQQkb12NK1aiJdjLYSC_RgSw"
    }
}