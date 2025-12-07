package dto.login;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequestDTO
{
    @NotBlank(message = "The username is required")
    String username;
    @NotBlank(message = "The password is required")
    String password;
}
