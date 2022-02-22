package io.github.sevenparadigms.abac.security.abac.data

import org.springframework.data.r2dbc.repository.R2dbcRepository
import org.springframework.data.repository.NoRepositoryBean
import org.springframework.transaction.annotation.Transactional
import reactor.core.publisher.Flux
import java.util.*

@NoRepositoryBean
interface AbacRuleRepository : R2dbcRepository<AbacRule, UUID> {
    @Transactional(readOnly = true)
    fun findAllByDomainType(domainType: String): Flux<AbacRule>
}