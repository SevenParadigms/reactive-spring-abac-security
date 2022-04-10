package io.github.sevenparadigms.abac.security.support.config

import org.junit.jupiter.api.extension.ExtendWith
import org.sevenparadigms.cache.hazelcast.HazelcastCacheConfiguration
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ContextConfiguration(classes = [HazelcastCacheConfiguration::class, AuthConfiguration::class])
@ExtendWith(SpringExtension::class)
open class AbstractTestEnvironment