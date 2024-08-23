package alexdev.authenticationprovider.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class UserHttp {

    private final UserService service;

    public UserHttp(UserService service) {
        this.service = service;
    }

    @GetMapping("/health")
    String health() {
        return "OK";
    }

    @GetMapping("/user")
    ResponseEntity<List<User>> listAll() {
        return ResponseEntity.ok(service.listAll());
    }

    @PostMapping("/user")
    void create(@RequestBody User user) {
        service.create(user);
    }
}
