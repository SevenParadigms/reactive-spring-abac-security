package io.github.sevenparadigms.abac.security.opaque.listener

import io.github.sevenparadigms.abac.security.cache.data.RevokeTokenEvent
import io.github.sevenparadigms.abac.security.cache.exception.NotFoundInCacheException
import io.github.sevenparadigms.abac.security.cache.service.TokenCacheService
import io.github.sevenparadigms.abac.security.opaque.data.OpaqueTokenPrincipal
import io.github.sevenparadigms.abac.security.opaque.data.TokenStatus
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.Mockito
import org.mockito.Mockito.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ApplicationEventMulticaster
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class EventListenerImplTest {

    @Qualifier("mockTokenCacheService")
    @Autowired
    private lateinit var mockCacheService: TokenCacheService

    @Autowired
    private lateinit var listener: ApplicationListener<RevokeTokenEvent>

    @Autowired
    private lateinit var multicaster: ApplicationEventMulticaster

    @BeforeEach
    fun reset() {
        Mockito.reset(mockCacheService)
    }

    @Test
    fun `listen when token exists`() {
        Mockito.doNothing().`when`(mockCacheService).revokeSyncToken(Mockito.anyString())
        val createdToken = createToken()

        multicaster.multicastEvent(createdToken)
        Thread.sleep(100)
        verify(mockCacheService).revokeSyncToken("new")
    }

    @Test
    fun `listen when token doesn't exists`() {
        Mockito.doThrow(NotFoundInCacheException("Token must be in the cache")).`when`(mockCacheService)
            .revokeSyncToken(Mockito.anyString())
        val createdToken = createToken()

        assertThrows(NotFoundInCacheException::class.java) { listener.onApplicationEvent(createdToken) }
    }

    private fun createToken(): RevokeTokenEvent {
        return RevokeTokenEvent(token = "new", source = OpaqueTokenPrincipal(TokenStatus.INVALID))
    }
}

