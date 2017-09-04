package org.angry1980.security.jwt

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import java.util.Objects

/**
 * Wrapper for signed json web token compatible with spring security solution
 */
class JwtAuthenticationToken(
        val token: Jws<Claims>,
        val user: User? = null,
        authorities: Collection<GrantedAuthority>? = null
) : AbstractAuthenticationToken(authorities) {

    init {
        if(user != null){
            isAuthenticated = true
        }
    }

    override fun getCredentials() = token

    override fun getPrincipal() = user

}
