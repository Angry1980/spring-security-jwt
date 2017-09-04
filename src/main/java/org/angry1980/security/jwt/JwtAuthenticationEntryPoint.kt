package org.angry1980.security.jwt

import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.AuthenticationEntryPoint
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Handler which is used when it's not possible to get any info about user
 */
class JwtAuthenticationEntryPoint : AuthenticationEntryPoint {

    val LOG = LoggerFactory.getLogger(JwtAuthenticationEntryPoint::class.java)

    override fun <T> commence(exchange: ServerWebExchange, e: AuthenticationException) = Mono.empty<T>().apply {
        LOG.info("Error while handling {}: {}", exchange.requestInfo(), e.message)
        exchange.response.statusCode = HttpStatus.UNAUTHORIZED
    }

}
