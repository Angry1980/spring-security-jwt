package org.angry1980.security.jwt

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

/**
 * Create list of roles based on info contained in json web token
 */
class JwtAuthenticationProvider : AuthenticationProvider {

    val LOG = LoggerFactory.getLogger(JwtAuthenticationProvider::class.java)

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val token = authentication.credentials as Jws<Claims>
        val scopes = token.body["scopes"] as List<String>
        val authorities = scopes
                .map { "ROLE_$it" }
                .map { SimpleGrantedAuthority(it) }
        val user = User(token.body.subject, "", authorities)
        LOG.debug("Request from user: {}", user)
        return JwtAuthenticationToken(token, user, authorities)
    }

    override fun supports(_class: Class<*>) = JwtAuthenticationToken::class.java.isAssignableFrom(_class)

}
