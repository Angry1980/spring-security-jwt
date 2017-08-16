package org.angry1980.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Objects;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Jws<Claims> token;
    private final User user;

    public JwtAuthenticationToken(Jws<Claims> token,
                                  User user,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = Objects.requireNonNull(token);
        this.user = Objects.requireNonNull(user);
        this.setAuthenticated(true);

    }

    public JwtAuthenticationToken(Jws<Claims> token) {
        super(null);
        this.token = Objects.requireNonNull(token);
        this.user = null;
        this.setAuthenticated(false);
    }

    public Object getCredentials() {
        return token;
    }

    public Object getPrincipal() {
        return user;
    }
}
