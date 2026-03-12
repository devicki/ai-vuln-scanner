package com.example.vulnerable;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/user")
    public String getUser(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        return result.toString();
    }
}
