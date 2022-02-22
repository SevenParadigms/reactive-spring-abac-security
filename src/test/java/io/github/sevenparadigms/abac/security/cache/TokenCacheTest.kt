package io.github.sevenparadigms.abac.security.cache

import com.google.common.cache.Cache
import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.support.config.OpaqueCacheConfiguration
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ContextConfiguration(classes = [OpaqueCacheConfiguration::class])
@ExtendWith(SpringExtension::class)
class TokenCacheTest {

    private val cache = TokenCache(1800)

    @Test
    fun getName() {
        Assertions.assertEquals(Constants.TOKEN_CACHE, cache.name)
    }

    @Test
    fun put_whenOk() {
        Assertions.assertDoesNotThrow { cache.put("any", "Any") }
    }

    @Test
    fun put_whenNullValue() {
        Assertions.assertThrows(IllegalArgumentException::class.java) { cache.put("any", null) }
    }

    @Test
    fun get_whenOk() {
        val expected = "Any"
        cache.put("any", expected)
        val actual = cache.get("any")!!.get() as String
        Assertions.assertEquals(expected, actual)
    }

    @Test
    fun clearByKey() {
        val expected = "any"
        cache.put(expected, "Any")
        cache.evict(expected)
        Assertions.assertNull(cache.get(expected))
    }

    @Test
    fun clearAll() {
        for (i in 1..5) {
            cache.put("any$i", "Any")
        }
        cache.clear()
        val nativeCache = cache.nativeCache as Cache<*, *>
        Assertions.assertEquals(0, nativeCache.size())
    }

}