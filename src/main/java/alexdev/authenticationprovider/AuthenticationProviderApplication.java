package alexdev.authenticationprovider;

import alexdev.authenticationprovider.user.Role;
import alexdev.authenticationprovider.user.User;
import alexdev.authenticationprovider.user.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthenticationProviderApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationProviderApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(Users repository, PasswordEncoder encoder) {
		return new CommandLineRunner() {
			@Override
			public void run(String... args) throws Exception {
				var user = new User();
				user.setUsername("user");
				user.setPassword(encoder.encode("123456"));
				user.setRole(Role.USER);
				repository.save(user);

				var admin = new User();
				admin.setUsername("admin");
				admin.setPassword(encoder.encode("123456"));
				admin.setRole(Role.ADMIN);
				repository.save(admin);

				repository.findAll().forEach(System.out::println);
			}
		};
	}

}
