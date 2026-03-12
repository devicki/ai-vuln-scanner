package com.example.unreachable;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/user")
public class UserController {
    private UserService userService = new UserService();

    @GetMapping("/{id}")
    public String getUser(@PathVariable String id) {
        return userService.findUser(id);
    }
}
