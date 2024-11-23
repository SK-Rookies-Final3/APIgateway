package com.shoppingoo.brand.domain.filestorage.service;

import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface FileStorageService {

    String saveImageFile(MultipartFile file) throws IOException;
}
