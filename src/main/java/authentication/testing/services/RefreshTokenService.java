package authentication.testing.services;

import authentication.testing.model.entity.RefreshToken;
import authentication.testing.model.entity.User;
import authentication.testing.repositories.RefreshTokenRepository;
import authentication.testing.repositories.UserRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            JwtService jwtService
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    /*public RefreshToken createRefreshToken(String email){
        RefreshToken refreshToken;
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        Optional<RefreshToken> existingTokenOptional = refreshTokenRepository.findByUser(user);

        if (existingTokenOptional.isPresent()){
            refreshToken = existingTokenOptional.get();
            refreshToken.setToken(UUID.randomUUID().toString());
            refreshToken.setExpiryDate(Instant.now().plus(1, ChronoUnit.HOURS));
        } else {
            refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(UUID.randomUUID().toString())
                    .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))  //plusMillis(6000)) v
                    .build();
        }

        return refreshTokenRepository.save(refreshToken);
    }*/

    public RefreshToken createRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

        Optional<RefreshToken> existingTokenOptional = refreshTokenRepository.findByUser(user);
        RefreshToken refreshToken;

        if (existingTokenOptional.isPresent()) {
            refreshToken = existingTokenOptional.get();
            refreshToken.setToken(jwtService.generateRefreshToken(user));
            refreshToken.setExpiryDate(Instant.now().plus(1, ChronoUnit.HOURS));
        } else {
            refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(jwtService.generateRefreshToken(user))
                    .expiryDate(Instant.now().plus(1, ChronoUnit.HOURS))
                    .build();
        }

        return refreshTokenRepository.save(refreshToken);
    }


    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token){
        if (token.getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token is expired.Please make a new login...!");
        }
        return token;
    }
}
