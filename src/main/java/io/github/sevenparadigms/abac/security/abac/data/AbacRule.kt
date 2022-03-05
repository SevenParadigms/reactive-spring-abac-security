package io.github.sevenparadigms.abac.security.abac.data

import org.springframework.expression.Expression
import java.util.*

data class AbacRule(
    var id: UUID,
    var name: String,
    var domainType: String,
    var target: Expression,
    var condition: Expression
)