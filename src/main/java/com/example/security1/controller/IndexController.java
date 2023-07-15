package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"", "/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public User user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        return principalDetails.getUser();
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    @GetMapping("/login")
    public String login(){
        return "loginForm";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/join")
    public String join() {
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProc(User user) {
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return "redirect:/";
    }

    @Secured("ROLE_ADMIN")  // 해당 권한을 가진 유저만 접근 허용: 간단하게 표시 가능
    @GetMapping("/info")
    @ResponseBody
    public String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data(){
        return "data";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testLogin(
            Authentication authentication,  // DI 의존성 주입
            @AuthenticationPrincipal OAuth2User oauth
            ){
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("Authentication: " + oauth2User.getAttributes());
        System.out.println("OAuth2User: " + oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

}
