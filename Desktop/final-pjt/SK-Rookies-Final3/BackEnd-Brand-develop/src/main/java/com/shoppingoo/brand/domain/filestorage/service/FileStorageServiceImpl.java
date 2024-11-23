package com.shoppingoo.brand.domain.filestorage.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Service
public class FileStorageServiceImpl implements FileStorageService {

    @Override
    // 이미지 파일을 로컬 디렉토리에 저장
    public String saveImageFile(MultipartFile file) throws IOException {
        // 파일 저장 경로 설정 (여기서는 'uploads' 폴더에 저장)
        String uploadDir = "uploads/";
        File directory = new File(uploadDir);

        // 폴더가 없으면 생성
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // 파일 이름 생성 (UUID 등을 이용할 수 있음)
        String fileName = System.currentTimeMillis() + "-" + file.getOriginalFilename();

        // 파일 저장
        File dest = new File(directory, fileName);
        file.transferTo(dest);

        // 저장된 파일의 URL 또는 경로 반환
        return uploadDir + fileName;
    }
}
