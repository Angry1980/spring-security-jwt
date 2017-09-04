package org.springframework.security.config.web.server

import org.angry1980.security.jwt.JwtAuthenticationConverter
import org.angry1980.security.jwt.JwtAuthenticationEntryPoint
import org.angry1980.security.jwt.JwtAuthenticationProvider
import org.angry1980.security.jwt.JwtExceptionTranslationWebFilter
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter
import org.springframework.security.authorization.AuthenticatedAuthorizationManager
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.ReactiveAuthorizationManager
import org.springframework.security.web.server.MatcherSecurityWebFilterChain
import org.springframework.security.web.server.SecurityWebFilterChain
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
 * Builder which is used by defining permissions for different resources.

 * Spring [org.springframework.security.config.web.server.HttpSecurity] was used as prototype.
 */
class HttpJwtSecurity(val signingKey: String) {

    private var securityMatcher = ServerWebExchangeMatchers.anyExchange()

    private var authorizeExchangeBuilder: AuthorizeExchangeBuilder? = null

    private val headers = HeaderBuilder()

    private var securityContextRepository: SecurityContextRepository? = null
    private val authenticationProviders = listOf(JwtAuthenticationProvider())

    fun securityMatcher(matcher: ServerWebExchangeMatcher) = this.apply {
        this.securityMatcher = matcher
    }

    fun securityContextRepository(securityContextRepository: SecurityContextRepository) = this.apply {
        this.securityContextRepository = securityContextRepository
    }

    fun headers() = headers

    fun authorizeExchange(): AuthorizeExchangeBuilder {
        if (authorizeExchangeBuilder == null) {
            authorizeExchangeBuilder = AuthorizeExchangeBuilder()
        }
        return authorizeExchangeBuilder!!
    }

    /**

     * @return instance of [SecurityWebFilterChain]
     */
    fun build(): SecurityWebFilterChain {
        val entryPoint = JwtAuthenticationEntryPoint()
        val successHandler = DefaultAuthenticationSuccessHandler()
        securityContextRepository?.apply { successHandler.setSecurityContextRepository(this) }
        val filters = mutableListOf(
            headers.build(),
            securityContextRepository?.let { SecurityContextRepositoryWebFilter(it) },
            authenticationFilter().apply {
                setEntryPoint(entryPoint)
                setAuthenticationConverter(JwtAuthenticationConverter(signingKey))
                setAuthenticationSuccessHandler(successHandler)
            },
            authorizeExchangeBuilder?.let { JwtExceptionTranslationWebFilter(entryPoint) },
            authorizeExchangeBuilder?.build()
        ).filterNotNull()
        return MatcherSecurityWebFilterChain(securityMatcher, filters)
    }

    private fun authenticationFilter() = AuthenticationWebFilter(
            ReactiveAuthenticationManagerAdapter(
                ProviderManager(authenticationProviders)
            )
    )



    inner class AuthorizeExchangeBuilder {
        private val managerBldr = DelegatingReactiveAuthorizationManager.builder()
        private var matcher: ServerWebExchangeMatcher? = null
        private var anyExchangeRegistered: Boolean = false

        fun and() = this@HttpJwtSecurity

        private fun matcher(matcher: ServerWebExchangeMatcher) = registerMatcher(matcher)

        fun anyExchange(): Access {
            val result = matcher(ServerWebExchangeMatchers.anyExchange())
            anyExchangeRegistered = true
            return result
        }

        fun pathMatchers(vararg antPatterns: String) = matcher(ServerWebExchangeMatchers.pathMatchers(*antPatterns))

        fun registerMatcher(matcher: ServerWebExchangeMatcher) = when {
            anyExchangeRegistered -> throw IllegalStateException("Cannot register $matcher which would be unreachable because anyExchange() has already been registered.")
            this.matcher != null ->  throw IllegalStateException("The matcher $matcher does not have an access rule defined")
            else -> {
                this.matcher = matcher
                Access()
            }
        }

        fun build() = when (this.matcher) {
            null -> AuthorizationWebFilter(managerBldr.build())
            else -> throw IllegalStateException("The matcher $matcher does not have an access rule defined")
        }

        inner class Access {

            fun permitAll() = access(ReactiveAuthorizationManager { a, e -> Mono.just(AuthorizationDecision(true)) })

            fun denyAll() = access(ReactiveAuthorizationManager { a, e -> Mono.just(AuthorizationDecision(false)) })

            fun hasRole(role: String) = access(AuthorityAuthorizationManager.hasRole<AuthorizationContext>(role))

            fun hasAuthority(authority: String) = access(AuthorityAuthorizationManager.hasAuthority<AuthorizationContext>(authority))

            fun authenticated() = access(AuthenticatedAuthorizationManager.authenticated<AuthorizationContext>())

            fun access(manager: ReactiveAuthorizationManager<AuthorizationContext>): AuthorizeExchangeBuilder {
                managerBldr.add(ServerWebExchangeMatcherEntry(matcher, manager))
                matcher = null
                return this@AuthorizeExchangeBuilder
            }
        }
    }

}
