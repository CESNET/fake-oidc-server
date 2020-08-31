package cz.metacentrum.fake_oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="oidc")
public class FakeOidcServerProperties {

    private User user;
    private long tokenExpirationSeconds;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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
                "user=" + user +
                ", tokenExpirationSeconds=" + tokenExpirationSeconds +
                '}';
    }
}
