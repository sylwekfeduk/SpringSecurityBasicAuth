package pl.fis.lbd.springsecurity.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/user")
public class UserController {

    @GetMapping
    public String getUser() {
        return "This is user!";
    }

    @PutMapping
    public String updateUser() {
        return "User updated!";
    }
}
