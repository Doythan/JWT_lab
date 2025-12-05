package com.pharmacy.spring_jwt.service;

import com.pharmacy.spring_jwt.entity.Medicine;
import com.pharmacy.spring_jwt.repository.MedicineRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MedicineService {
    
    private final MedicineRepository medicineRepository;
    
    public List<Medicine> getAllMedicines() {
        return medicineRepository.findAll();
    }
    
    public Medicine getMedicineById(Long id) {
        return medicineRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("약품을 찾을 수 없습니다."));
    }
}