package io.github.sevenparadigms.abac.security.auth.data

import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.r2dbc.repository.R2dbcRepository
import org.springframework.data.repository.NoRepositoryBean
import reactor.core.publisher.Mono
import java.util.*

@NoRepositoryBean
interface UserRepository : R2dbcRepository<UserPrincipal, UUID> {
    @Query("""SELECT lu.*, ARRAY_TO_JSON(ARRAY_AGG(au.*)) as authorities FROM local_user lu
            JOIN authority_user ON user_id = lu.id 
            JOIN authority au ON authority_id = au.id
            GROUP BY lu.id, lu.login, lu.password HAVING login = :login""")
    fun findByLogin(login: String): Mono<UserPrincipal>
}