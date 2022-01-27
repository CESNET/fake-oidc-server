package cz.metacentrum.fake_oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix="oidc")
public class FakeOidcServerProperties {

    private List<User> users;
    private long tokenExpirationSeconds;

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    public long getTokenExpirationSeconds() {
        return tokenExpirationSeconds;
    }

    public void setTokenExpirationSeconds(long tokenExpirationSeconds) {
        this.tokenExpirationSeconds = tokenExpirationSeconds;
    }

    @Override
    public String toString() {
        return "FakeOidcServerProperties{" +
                "users=" + users +
                ", tokenExpirationSeconds=" + tokenExpirationSeconds +
                '}';
    }
}
