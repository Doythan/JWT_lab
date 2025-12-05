package com.pharmacy.spring_jwt.config;

import com.pharmacy.spring_jwt.entity.Medicine;
import com.pharmacy.spring_jwt.entity.User;
import com.pharmacy.spring_jwt.repository.MedicineRepository;
import com.pharmacy.spring_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {
    
    private final UserRepository userRepository;
    private final MedicineRepository medicineRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Override
    public void run(String... args) {
        // Test user
        User user1 = User.builder()
                .username("doythan")
                .password(passwordEncoder.encode("1234"))
                .name("Doythan")
                .email("doythan@pharmacy.com")
                .role(User.Role.ROLE_USER)
                .build();
        
        User admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin1234"))
                .name("Admin")
                .email("admin@pharmacy.com")
                .role(User.Role.ROLE_ADMIN)
                .build();
        
        userRepository.save(user1);
        userRepository.save(admin);
        
        // Test medicine data
        Medicine med1 = Medicine.builder()
                .name("Tylenol")
                .manufacturer("Johnson & Johnson Korea")
                .stock(100)
                .price(5000)
                .build();
        
        Medicine med2 = Medicine.builder()
                .name("Gevolin")
                .manufacturer("Samjin Pharm")
                .stock(50)
                .price(3000)
                .build();
        
        Medicine med3 = Medicine.builder()
                .name("Zyrtec")
                .manufacturer("UCB Korea")
                .stock(80)
                .price(8000)
                .build();
        
        medicineRepository.save(med1);
        medicineRepository.save(med2);
        medicineRepository.save(med3);
        
        System.out.println("===== Test Data Initialization Complete =====");
        System.out.println("User1 - username: doythan, password: 1234");
        System.out.println("Admin - username: admin, password: admin1234");
        System.out.println("3 medicines created");
    }
}