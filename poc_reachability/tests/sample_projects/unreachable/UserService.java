package com.example.unreachable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserService {
    private static final Logger logger = LogManager.getLogger(UserService.class);

    public String findUser(String id) {
        logger.info("Finding user: " + id);
        return "User: " + id;
    }
}
