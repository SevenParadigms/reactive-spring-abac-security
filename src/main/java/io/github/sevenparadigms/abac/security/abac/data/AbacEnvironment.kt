package io.github.sevenparadigms.abac.security.abac.data

import java.time.LocalDate
import java.time.LocalDateTime

data class AbacEnvironment(
    val date: LocalDate = LocalDate.now(),
    val now: LocalDateTime = LocalDateTime.now(),
    val ip: String?
)