package pl.fis.lbd.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/admin")
public class AdminController {

    @GetMapping
    public String getAdmin() {
        return "This is admin!";
    }

    @PutMapping
    public String createUser() {
        return "User created!";
    }

    @DeleteMapping
    public String deleteUser() {
        return "User deleted!";
    }
}
