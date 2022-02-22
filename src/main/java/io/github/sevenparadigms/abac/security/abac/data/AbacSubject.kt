package io.github.sevenparadigms.abac.security.abac.data

data class AbacSubject(
    var username: String,
    var roles: Set<String>
)