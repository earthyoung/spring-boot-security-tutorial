package com.example.security1.config;


import com.example.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity  // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableMethodSecurity(securedEnabled = true)
// @Secured 어노테이션을 활성화시켜서 컨트롤러의 특정 메소드에다 @Secured(권한) 을 붙이면 특정 권한에만 허용함
// prePostEnabled=true 이므로 이미 @preAuthorize, @PostAuthorize 어노테이션 사용 가능
// @PreAuthorize: 메소드 실행 직전 권한 검증
// @PostAuthorize: 메소드 실행 직후 권한 검증
public class SecurityConfig {

    @Autowired
    public PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable());
        http
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/login", "/loginForm", "/loginProc", "/join", "/joinProc", "/user").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin((formLogin) ->
                        formLogin
                                .loginPage("/loginForm")
                                .loginProcessingUrl("/loginProc")
                                .defaultSuccessUrl("/"))
                .oauth2Login((oauth2Login) ->
                        oauth2Login
                                .loginPage("/loginForm")
                                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService(principalOauth2UserService))
                )
                .httpBasic(withDefaults());
        return http.build();
    }

}
