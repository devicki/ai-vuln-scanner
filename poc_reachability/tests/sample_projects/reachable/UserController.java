package com.example.reachable;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/user")
public class UserController {
    private LogService logService = new LogService();

    @GetMapping("/{id}")
    public String getUser(@PathVariable String id) {
        logService.log("Fetching user: " + id);
        return "User: " + id;
    }
}
