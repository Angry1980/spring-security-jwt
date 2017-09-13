package org.angry1980.security.jwt

import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.web.server.AuthenticationEntryPoint
import org.springframework.security.web.server.authorization.AccessDeniedHandler
import org.springframework.security.web.server.authorization.HttpStatusAccessDeniedHandler
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.security.Principal

/**
 * Handler of authorization errors
 */
class JwtExceptionTranslationWebFilter (val entryPoint: AuthenticationEntryPoint,
                                        val accessDeniedHandler: AccessDeniedHandler = HttpStatusAccessDeniedHandler(HttpStatus.FORBIDDEN)) : WebFilter {

    val LOG = LoggerFactory.getLogger(JwtExceptionTranslationWebFilter::class.java)

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain) = chain.filter(exchange)
            .onErrorResume(AccessDeniedException::class.java) { e ->
                exchange.getPrincipal<Principal>()
                        // user was not authenticated
                        .switchIfEmpty(
                                Mono.defer { entryPoint.commence<Principal>(exchange, AuthenticationCredentialsNotFoundException("Not Authenticated", e)) }
                        )
                        // user is authenticated but does not have enough rights to get access to resource
                        .flatMap {
                            LOG.info("Access for {} to {} is denied", it.getName(), exchange.requestInfo())
                            accessDeniedHandler.handle<Void>(exchange, e)
                        }

            }

}
