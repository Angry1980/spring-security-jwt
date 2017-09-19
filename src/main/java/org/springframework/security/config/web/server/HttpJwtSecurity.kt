package org.springframework.security.config.web.server

import org.angry1980.security.jwt.JwtAuthenticationConverter
import org.angry1980.security.jwt.JwtAuthenticationEntryPoint
import org.angry1980.security.jwt.JwtAuthenticationProvider
import org.angry1980.security.jwt.JwtExceptionTranslationWebFilter
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authorization.AuthenticatedAuthorizationManager
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.ReactiveAuthorizationManager
import org.springframework.security.web.server.AuthenticationEntryPoint
import org.springframework.security.web.server.MatcherSecurityWebFilterChain
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.DefaultAuthenticationSuccessHandler
import org.springframework.security.web.server.authorization.AuthorizationContext
import org.springframework.security.web.server.authorization.AuthorizationWebFilter
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager
import org.springframework.security.web.server.context.SecurityContextRepository
import org.springframework.security.web.server.context.SecurityContextRepositoryWebFilter
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import reactor.core.publisher.Mono

/**
 * Builder which is used to define permissions for different resources.
 *
 * Spring [org.springframework.security.config.web.server.HttpSecurity] was used as prototype.
 */
class HttpJwtSecurity(val signingKey: String,
                      var securityMatcher: ServerWebExchangeMatcher = ServerWebExchangeMatchers.anyExchange(),
                      var securityContextRepository: SecurityContextRepository? = null,
                      val authenticationProviders: List<AuthenticationProvider> = listOf(JwtAuthenticationProvider())) {

    val authorizeExchangeBuilder = AuthorizeExchangeBuilder()
    val headers: HeaderBuilder = HeaderBuilder()

    fun build(namespace: String, role: String) = this.apply {
        securityMatcher = ServerWebExchangeMatchers.pathMatchers(namespace)
        authorizeExchangeBuilder.anyExchange().hasRole(role)
    }.build()

    /**
     *
     * @return instance of [SecurityWebFilterChain]
     */
    fun build(): SecurityWebFilterChain {
        val entryPoint = JwtAuthenticationEntryPoint()
        val successHandler = DefaultAuthenticationSuccessHandler()
        securityContextRepository?.apply { successHandler.setSecurityContextRepository(this) }
        val filters = listOf(
                headers.build(),
                securityContextRepository?.let { SecurityContextRepositoryWebFilter(it) },
                authenticationFilter(entryPoint, successHandler),
                JwtExceptionTranslationWebFilter(entryPoint),
                authorizeExchangeBuilder.build()
        ).filterNotNull()
        return MatcherSecurityWebFilterChain(securityMatcher, filters)
    }

    private fun authenticationFilter(entryPoint: AuthenticationEntryPoint,
                                     successHandler: AuthenticationSuccessHandler) = ReactiveAuthenticationManagerAdapter(
            ProviderManager(authenticationProviders)
    ).let {
        AuthenticationWebFilter(it)
    }.apply {
        setEntryPoint(entryPoint)
        setAuthenticationConverter(JwtAuthenticationConverter(signingKey))
        setAuthenticationSuccessHandler(successHandler)
    }

}

class AuthorizeExchangeBuilder {
    private val managerBldr = DelegatingReactiveAuthorizationManager.builder()
    private var matcher: ServerWebExchangeMatcher? = null
    private var anyExchangeRegistered: Boolean = false

    fun anyExchange() = registerMatcher(ServerWebExchangeMatchers.anyExchange())
            .apply {
                anyExchangeRegistered = true
            }

    fun pathMatchers(vararg antPatterns: String) = registerMatcher(ServerWebExchangeMatchers.pathMatchers(*antPatterns))

    fun registerMatcher(matcher: ServerWebExchangeMatcher) = when {
        anyExchangeRegistered -> throw IllegalStateException("Cannot register $matcher which would be unreachable because anyExchange() has already been registered.")
        this.matcher != null  -> throw IllegalStateException("The matcher $matcher does not have an access rule defined")
        else -> {
            this.matcher = matcher
            Access()
        }
    }

    fun build() = when(this.matcher){
        null -> AuthorizationWebFilter(managerBldr.build())
        else -> throw IllegalStateException("The matcher $matcher does not have an access rule defined")
    }

    inner class Access {

        fun permitAll() = access(ReactiveAuthorizationManager{ _, _ -> Mono.just(AuthorizationDecision(true)) })

        fun denyAll() = access(ReactiveAuthorizationManager{ _, _ -> Mono.just(AuthorizationDecision(false)) })

        fun hasRole(role: String) = access(AuthorityAuthorizationManager.hasRole(role))

        fun hasAuthority(authority: String) = access(AuthorityAuthorizationManager.hasAuthority(authority))

        fun authenticated() = access(AuthenticatedAuthorizationManager.authenticated())

        fun access(manager: ReactiveAuthorizationManager<AuthorizationContext>) = this@AuthorizeExchangeBuilder
                .apply {
                    managerBldr.add(ServerWebExchangeMatcherEntry(matcher, manager))
                    matcher = null
                }
    }

}

