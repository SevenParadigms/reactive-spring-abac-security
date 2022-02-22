package io.github.sevenparadigms.abac.security.cache

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class TokenCacheManagerTest {

    @Autowired
    private lateinit var cacheManager: TokenCacheManager

    @Test
    fun getCache_whenNameExists() {
        val actual = cacheManager.getCache(Constants.TOKEN_CACHE)
        Assertions.assertNotNull(actual)
    }

    @Test
    fun getCache_whenNameNotExists() {
        val actual = cacheManager.getCache("asdasd")
        Assertions.assertNotNull(actual)
    }
}