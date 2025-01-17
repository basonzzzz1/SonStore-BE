package com.example.ecommerce_supper.sevice.seviceIMPL;
import com.example.ecommerce_supper.models.User;
import com.example.ecommerce_supper.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;
    public boolean existsByUsername(String username){
        return userRepository.existsByUsername(username);
    }
    public User save(User user){
        return userRepository.save(user);
    }
    public Boolean existsByPhone(String phone){
        return userRepository.existsByPhone(phone);
    }
    public User findByUsernameAndPassword(String username , String password){
        return userRepository.findByUsernameAndPassword(username , password).get();
    }
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
    public Optional<User> findByUsername(String userName){
        return userRepository.findByUsername(userName);
    }
    public Optional<User> getLoggedInUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // Kiểm tra xem đối tượng có được xác thực hay không
        if (authentication != null && authentication.isAuthenticated()) {
            // Lấy tên đăng nhập của đối tượng đang đăng nhập
             String username = authentication.getName();
             return userRepository.findByUsername(username);
        }
        // Trường hợp không có ai đăng nhập
        throw new RuntimeException("Error Exception Principal !");
    }
    public List<User> findAll(){
        return userRepository.findAll();
    }
}