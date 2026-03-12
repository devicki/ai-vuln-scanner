package com.example.safe;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
public class SafeUserController {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/safe/user")
    public String getUser(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = ?";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query, userId);
        return result.toString();
    }
}
