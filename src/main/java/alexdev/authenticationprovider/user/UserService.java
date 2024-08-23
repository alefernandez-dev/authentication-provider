package alexdev.authenticationprovider.user;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final Users repository;
    private final PasswordEncoder encoder;

    public UserService(Users repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    List<User> listAll() {
        return repository.findAll();
    }

    void create(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        repository.save(user);
    }
}
