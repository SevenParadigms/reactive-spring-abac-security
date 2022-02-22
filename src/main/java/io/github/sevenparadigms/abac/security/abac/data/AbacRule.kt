package io.github.sevenparadigms.abac.security.abac.data

import java.util.*

data class AbacRule(
    var id: UUID,
    var name: String,
    var domainType: String,
    var target: String,
    var condition: String
)