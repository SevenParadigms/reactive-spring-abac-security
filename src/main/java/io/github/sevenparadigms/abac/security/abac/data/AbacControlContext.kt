package io.github.sevenparadigms.abac.security.abac.data

data class AbacControlContext(
    var subject: AbacSubject,
    var domainObject: Any,
    var action: String,
    var environment: AbacEnvironment
)