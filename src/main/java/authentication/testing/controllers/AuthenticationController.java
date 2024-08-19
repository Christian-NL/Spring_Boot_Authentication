package authentication.testing.controllers;


import authentication.testing.model.dtos.*;
import authentication.testing.model.entity.RefreshToken;
import authentication.testing.model.entity.User;
import authentication.testing.services.AuthenticationService;
import authentication.testing.services.TokenBlacklistedService;
import authentication.testing.services.JwtService;
import authentication.testing.services.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistedService tokenBlacklistedService;

    public AuthenticationController(
            JwtService jwtService,
            AuthenticationService authenticationService,
            RefreshTokenService refreshTokenService,
            TokenBlacklistedService tokenBlacklistedService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistedService = tokenBlacklistedService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDTO registerUserDTO) {
        User registeredUser = authenticationService.signup(registerUserDTO);

        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDTO loginUserDTO) {
        User authenticatedUser = authenticationService.authenticate(loginUserDTO);

        String jwtToken = jwtService.generateToken(authenticatedUser);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(authenticatedUser.getEmail());

        LoginResponse loginResponse = new LoginResponse()
                .setToken(jwtToken)
                .setRefreshToken(refreshToken.getToken())
                .setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<JwtResponse> refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO){
        return refreshTokenService.findByToken(refreshTokenRequestDTO.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String accessToken = jwtService.generateToken(user);
                    return ResponseEntity.ok(
                            JwtResponse.builder()
                                    .accessToken(accessToken)
                                    .token(refreshTokenRequestDTO.getToken())
                                    .build()
                    );
                }).orElseThrow( ()-> new RuntimeException("Refresh Token is not in DB..."));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader){
        if (authHeader == null || !authHeader.startsWith("Bearer")){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Token format...");
        }

        String token = authHeader.substring(7);
        tokenBlacklistedService.blacklistToken(token);
        return ResponseEntity.ok("Logged out successfully...");
    }
}
