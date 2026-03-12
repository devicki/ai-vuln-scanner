package com.example.vulnerable;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Controller
public class CommentController {
    @GetMapping("/comment")
    public void showComment(@RequestParam String comment, HttpServletResponse response) throws IOException {
        PrintWriter writer = response.getWriter();
        writer.write("<div>" + comment + "</div>");
    }
}
