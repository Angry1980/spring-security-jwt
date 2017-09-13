package org.angry1980.security.jwt

import org.springframework.web.server.ServerWebExchange

fun ServerWebExchange.requestInfo() = "${request.method} ${request.uri}"