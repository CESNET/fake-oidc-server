package cz.metacentrum.fake_oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Component
@ConfigurationProperties(prefix="oidc")
public class FakeOidcServerProperties {

    private Map<String,User> users;
    private long tokenExpirationSeconds;

    public Map<String, User> getUsers() {
        return users;
    }

    public void setUsers(Map<String, User> users) {
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

    @PostConstruct
    public void init() {
        for (Map.Entry<String, User> userEntry : users.entrySet()) {
            User user = userEntry.getValue();
            String login = userEntry.getKey();
            user.setLogname(login);
            user.setPreferred_username(login);
            user.setName(user.getGiven_name()+" "+user.getFamily_name());
        }
    }
}
