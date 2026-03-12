package com.example.safe;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Controller
public class SafeCommentController {
    @GetMapping("/safe/comment")
    public void showComment(@RequestParam String comment, HttpServletResponse response) throws IOException {
        PrintWriter writer = response.getWriter();
        String escaped = HtmlUtils.htmlEscape(comment);
        writer.write("<div>" + escaped + "</div>");
    }
}
