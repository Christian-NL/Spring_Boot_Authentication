package authentication.testing.model.dtos;

import lombok.Data;

@Data
public class RefreshTokenRequestDTO {
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
