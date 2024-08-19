package authentication.testing.services;

import authentication.testing.model.entity.BlacklistedToken;
import authentication.testing.repositories.BlacklistTokenRepositories;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TokenBlacklistedService {
    private final BlacklistTokenRepositories blacklistTokenRepository;

    public TokenBlacklistedService(BlacklistTokenRepositories blacklistTokenRepository){
        this.blacklistTokenRepository = blacklistTokenRepository;
    }

    public void blacklistToken(String token){
        BlacklistedToken blacklistedToken = new BlacklistedToken();
        blacklistedToken.setToken(token);
        blacklistTokenRepository.save(blacklistedToken);
    }

    public boolean isTokenBlaclisted(String token){
        Optional<BlacklistedToken> blacklistToken = blacklistTokenRepository.findByToken(token);
        return blacklistToken.isPresent();
    }
}
