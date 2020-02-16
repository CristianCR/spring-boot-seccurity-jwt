package es.cristian.security.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import es.cristian.security.model.User;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails {

    private Integer id;
    private String username;
    private String email;

    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public UserPrincipal(Integer id, String username, String email, Collection<? extends GrantedAuthority> authorities) {
        this(id, username, email, null, authorities);
    }

    public UserPrincipal(Integer id, String username, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    static UserPrincipal create(Claims claims) {
        return new UserPrincipal(
                (Integer) claims.get("id"),
                (String) claims.get("username"),
                (String) claims.get("email"),
                null,
                getGrantedAuthorities((ArrayList<LinkedHashMap>) claims.get("authorities"))
        );
    }

    static UserPrincipal create(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream().map(role ->
                new SimpleGrantedAuthority(role.getDescription())
        ).collect(Collectors.toList());

        return new UserPrincipal(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    public Integer getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserPrincipal that = (UserPrincipal) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    private static List<? extends GrantedAuthority> getGrantedAuthorities(ArrayList<LinkedHashMap> authorities) {
        List<? extends GrantedAuthority> grantedAuthorities = null;
        if (!CollectionUtils.isEmpty(authorities)) {
            grantedAuthorities = authorities.stream()
                    .map(authority ->
                            (GrantedAuthority) () ->
                                    (String) authority.get("authority"))
                    .collect(Collectors.toList());
        }
        return grantedAuthorities;
    }
}
