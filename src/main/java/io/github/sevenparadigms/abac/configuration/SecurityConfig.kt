package io.github.sevenparadigms.abac.configuration

import io.github.sevenparadigms.abac.Constants
import io.github.sevenparadigms.abac.Constants.ABAC_URL_PROPERTY
import io.github.sevenparadigms.abac.security.abac.data.AbacRuleRepository
import io.github.sevenparadigms.abac.security.abac.service.AbacRulePermissionService
import io.github.sevenparadigms.abac.security.auth.CurrentUserResolver
import io.github.sevenparadigms.abac.security.auth.encrypt.JwtTokenProvider
import io.github.sevenparadigms.abac.security.support.ConfigHelper
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
import org.springframework.data.r2dbc.repository.security.AuthenticationIdentifierResolver
import org.springframework.data.r2dbc.support.Beans
import org.springframework.data.r2dbc.support.R2dbcUtils
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
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
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.router

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@ComponentScan(basePackageClasses = [Constants::class])
@EnableConfigurationProperties(JwtProperties::class)
@ImportAutoConfiguration(Beans::class)
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
    fun authenticationWebFilter(authenticationManager: ReactiveAuthenticationManager, jwt: JwtProperties) =
        AuthenticationWebFilter(authenticationManager).also {
            it.setRequiresAuthenticationMatcher(jwtHeadersExchangeMatcher(jwt.headerAuthorize))
            it.setServerAuthenticationConverter(tokenAuthenticationConverter(jwt.headerAuthorize, jwtTokenProvider))
        }

    @Bean
    @ConditionalOnProperty(ABAC_URL_PROPERTY)
    fun abacRuleRepository(@Value("\${$ABAC_URL_PROPERTY}") url: String): AbacRuleRepository =
        R2dbcUtils.getRepository(url, AbacRuleRepository::class.java)

    @Bean
    @ConditionalOnProperty(ABAC_URL_PROPERTY)
    fun route(): RouterFunction<ServerResponse> = router {
        ("/token").nest {
            accept(MediaType.APPLICATION_JSON).nest {
                POST("", ::authorize)
            }
            accept(MediaType.APPLICATION_JSON).nest {
                GET("", ::refresh)
            }
        }
    }

    @Bean
    fun currentUserResolver(): AuthenticationIdentifierResolver = CurrentUserResolver()
}