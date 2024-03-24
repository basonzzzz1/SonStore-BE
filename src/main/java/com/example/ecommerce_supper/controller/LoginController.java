package com.example.ecommerce_supper.controller;

import com.example.ecommerce_supper.config.jwt.JwtUtils;
import com.example.ecommerce_supper.models.ERole;
import com.example.ecommerce_supper.models.Role;
import com.example.ecommerce_supper.models.User;
import com.example.ecommerce_supper.payload.request.BannerRequest;
import com.example.ecommerce_supper.payload.request.LoginRequest;
import com.example.ecommerce_supper.payload.request.SignupRequest;
import com.example.ecommerce_supper.payload.request.TokenRequest;
import com.example.ecommerce_supper.payload.response.JwtResponse;
import com.example.ecommerce_supper.payload.response.MessageResponse;
import com.example.ecommerce_supper.repository.RoleRepository;
import com.example.ecommerce_supper.sevice.seviceIMPL.UserDetailsImpl;
import com.example.ecommerce_supper.sevice.seviceIMPL.UserDetailsServiceImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/User")
public class LoginController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    SimpMessagingTemplate template;
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        User user = userDetailsService.findByUsername(userDetails.getUsername()).get();
        if (user.isBanned() == true) {
            user.setOnline(false);
        } else {
            user.setOnline(true);
        }
        userDetailsService.save(user);
        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getPhone(),
                user.isBanned(),
                user.getImage(),
                roles));
    }


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userDetailsService.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userDetailsService.existsByPhone(signUpRequest.getPhone())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Phone is already in use!"));
        }
        LocalDateTime lastTimeReset = LocalDateTime.now().minusDays(1);
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getPhone(),
                false,
                encoder.encode(signUpRequest.getPassword()), "https://inkythuatso.com/uploads/thumbnails/800/2023/03/8-anh-dai-dien-trang-inkythuatso-03-15-26-54.jpg");
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        User userSave = userDetailsService.save(user);
        return ResponseEntity.ok(userSave);
    }

    @PostMapping("/fail")
    public String checkUser(@RequestBody User user) { // login fail
        return checkErr(user);
    }

    public String checkErr(User user) {
        String err = "";
        if (userDetailsService.findByUsername(user.getUsername()).isPresent()) {
            if (userDetailsService.findByUsernameAndPassword(user.getUsername(), user.getPassword()) == null) {
                err = "wrong password";
            }
        } else {
            err = "wrong username";
        }
        return err;
    }

    @PostMapping("/logout")
    @PreAuthorize("hasAnyRole('USER') or hasAnyRole('ADMIN')")
    public ResponseEntity<?> logOut(@RequestBody String username) {
        User principal = userDetailsService.getLoggedInUser().get();
        principal.setOnline(false);
        userDetailsService.save(principal);
        return ResponseEntity.ok("đăng xuất thành công !");
    }

    @GetMapping("/findAllUser")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public List<User> findAllUser() {
        return userDetailsService.findAll();
    }


    @PostMapping("/banner")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<String> bannerUser(@RequestBody BannerRequest bannerRequest) {
        User user = userDetailsService.findByUsername(bannerRequest.getUsername()).get();
        user.setBanned(true);
        userDetailsService.save(user);
        return ResponseEntity.ok("khóa taì khoản :" + bannerRequest.getUsername() + " thành công !");
    }

    @PostMapping("/unBanner")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<String> unBannedUser(@RequestBody BannerRequest bannerRequest) {
        User user = userDetailsService.findByUsername(bannerRequest.getUsername()).get();
        user.setBanned(false);
        userDetailsService.save(user);
        return ResponseEntity.ok("mở taì khoản :" + bannerRequest.getUsername() + " thành công !");
    }

    @GetMapping("/loggedInUser")
    @PreAuthorize("hasAnyRole('USER') or hasAnyRole('ADMIN')")
    public User loggedInUser() {
        return userDetailsService.getLoggedInUser().get();
    }

    @GetMapping("/check-token")
    @PreAuthorize("hasAnyRole('USER') or hasAnyRole('ADMIN')")
    public ResponseEntity<Boolean> checkToken() {
        return ResponseEntity.ok(true);
    }
}