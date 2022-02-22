package io.github.sevenparadigms.abac.security.opaque.service.impl

import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.web.reactive.function.client.WebClient


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class TokenIntrospectionServiceImplTest {

    @Test
    fun `create instance`() {
        Assertions.assertThrows(IllegalArgumentException::class.java) { TokenIntrospectionServiceImpl(introspectionUrl = "url") }
        Assertions.assertThrows(IllegalArgumentException::class.java) {
            TokenIntrospectionServiceImpl(introspectionUrl = "url", introspectionSecret = "url")
        }
        Assertions.assertThrows(IllegalArgumentException::class.java) {
            TokenIntrospectionServiceImpl(introspectionUrl = "url", introspectionClientId = "url")
        }
        Assertions.assertDoesNotThrow {
            TokenIntrospectionServiceImpl(
                introspectionUrl = "url",
                introspectionClientId = "url",
                introspectionSecret = "secret"
            )
        }
        Assertions.assertDoesNotThrow {
            TokenIntrospectionServiceImpl(
                introspectionUrl = "url",
                webClient = WebClient.create()
            )
        }
    }

}