package io.github.sevenparadigms.abac.configuration

import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.context.annotation.Import

@EnableAutoConfiguration
@Import(SecurityConfig::class)
annotation class EnableAbacSecurity