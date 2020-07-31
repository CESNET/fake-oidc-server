package cz.metacentrum.fake_oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="oidc")
public class FakeOidcProperties {

    private User user;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "FakeOidcProperties{" +
                "user=" + user +
                '}';
    }
}
