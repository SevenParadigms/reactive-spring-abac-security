package io.github.sevenparadigms.abac.configuration

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.abac.service.AbacRulePermissionService
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.support.ConfigHelper
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.env.Environment
import org.springframework.data.r2dbc.config.Beans
import org.springframework.data.r2dbc.support.R2dbcUtils
import org.springframework.http.HttpMethod
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache
import org.springframework.web.reactive.function.server.RequestPredicates.POST
import org.springframework.web.reactive.function.server.RouterFunctions

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@ComponentScan(basePackageClasses = [Constants::class])
@Import(Beans::class)
class SecurityConfig(
    private val jwtTokenProvider: JwtTokenProvider
) : ConfigHelper() {
    @Bean
    fun securityWebFilterChain(
        http: ServerHttpSecurity,
        authenticationWebFilter: AuthenticationWebFilter,
        environment: Environment,
        expressionHandler: DefaultMethodSecurityExpressionHandler
    ): SecurityWebFilterChain {
        val abacRulePermissionService = Beans.of(AbacRulePermissionService::class.java, null)
        if (abacRulePermissionService != null) {
            expressionHandler.setPermissionEvaluator(abacRulePermissionService)
        }
        http.csrf().disable()
            .headers().frameOptions().disable()
            .cache().disable()
            .and()
            .exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint())
            .and()
            .authorizeExchange()
            .pathMatchers(HttpMethod.OPTIONS)
            .permitAll()
            .and()
            .requestCache().requestCache(NoOpServerRequestCache.getInstance())
            .and()
            .authorizeExchange()
            .matchers(EndpointRequest.toAnyEndpoint())
            .hasAuthority(Constants.ROLE_ADMIN)
            .and()
            .authorizeExchange()
            .pathMatchers(*Constants.whitelist).permitAll()
            .anyExchange().authenticated()
            .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHORIZATION)
            .httpBasic().disable()
            .formLogin().disable()
            .logout().disable()
        return super.tryAddTokenIntrospect(http).build()
    }

    @Bean
    fun authenticationWebFilter(authenticationManager: ReactiveAuthenticationManager) =
        AuthenticationWebFilter(authenticationManager).also {
            val isAuthorizeKeyEnabled = Beans.getProperty(Constants.AUTHORIZE_PROPERTY, Boolean::class.java, false)
            it.setRequiresAuthenticationMatcher(jwtHeadersExchangeMatcher(isAuthorizeKeyEnabled))
            it.setServerAuthenticationConverter(tokenAuthenticationConverter(isAuthorizeKeyEnabled, jwtTokenProvider))
        }

    @Bean
    @ConditionalOnProperty("spring.security.abac.url")
    fun abacRuleRepository(@Value("\${spring.security.abac.url}") url: String): AbacRuleRepository =
        R2dbcUtils.getRepository(url, AbacRuleRepository::class.java)

    @Bean
    fun auth() = RouterFunctions.route(POST("/auth"), ::authorize)

    @Bean
    fun opaqueToken() = RouterFunctions.route(POST("/auth/token/introspect"), ::validateOpaqueToken)
}