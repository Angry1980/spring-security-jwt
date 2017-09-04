package org.angry1980.security.jwt

import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.server.ServerWebExchange

val UTILS_LOG = LoggerFactory.getLogger("utils")

fun ServerWebExchange.requestInfo() = "${request.method} ${request.uri}"

fun ClientRequest.requestInfo() = "${method()} ${url()} "

fun HttpHeaders.print(request: Boolean = true) = forEach { name, values ->
    values.forEach { value -> UTILS_LOG.debug(if (request) "Request header {}: {}" else "Response header {}: {}", name, value) }
}
