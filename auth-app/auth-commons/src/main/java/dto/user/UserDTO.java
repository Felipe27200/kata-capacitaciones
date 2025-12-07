package dto.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO
{
    private Long id;

    private String username;
    private String fullName;
    private String password;
    private RoleDTO role;
}
