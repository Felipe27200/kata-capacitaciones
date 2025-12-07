package dto.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserDTO
{
    @NotBlank(message = "The username is required")
    private String username;
    @NotBlank(message = "The full name is required")
    private String fullName;
    @NotBlank(message = "The password is required")
    private String password;
    @NotNull(message = "The role is required")
    private Long roleFk;
}
