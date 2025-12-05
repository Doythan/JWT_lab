package com.pharmacy.spring_jwt.repository;

import com.pharmacy.spring_jwt.entity.Medicine;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MedicineRepository extends JpaRepository<Medicine, Long> {
}