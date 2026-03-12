package com.example.reachable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.lookup.JndiLookup;

public class LogService {
    private static final Logger logger = LogManager.getLogger(LogService.class);
    private JndiLookup jndiLookup = new JndiLookup();

    public void log(String message) {
        logger.info(message);
        String result = jndiLookup.lookup(message);
    }
}
