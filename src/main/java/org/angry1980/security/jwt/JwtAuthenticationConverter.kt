package org.angry1980.security.jwt

import io.jsonwebtoken.Jwts
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

import java.util.function.Function

/**
 * Function which is used to get info for authentication from http request
 */
class JwtAuthenticationConverter(val signingKey: String) : Function<ServerWebExchange, Mono<Authentication>> {

    val LOG = LoggerFactory.getLogger(JwtAuthenticationConverter::class.java)

    override fun apply(exchange: ServerWebExchange) = Mono.defer<Authentication> {
        // get values of Authorization header
        exchange.request.headers[HttpHeaders.AUTHORIZATION]
                // choose the first one which starts with token type prefix
                ?. first { it.startsWith("Bearer ") }
                // get value of token
                ?. substring(7)
                // parse jwt
                ?. let { Jwts.parser().setSigningKey(signingKey).parseClaimsJws(it) }
                ?. also { LOG.debug("Json web token: {}", it) }
                // wrap parsed jwt by object which implements spring Authentication interface
                ?. let { Mono.just(JwtAuthenticationToken(it)) }
                ?: Mono.empty()
    }.onErrorResume {
        LOG.error("Error while parsing jwt token for {}", exchange.requestInfo(), it)
        Mono.empty()
    }

}
