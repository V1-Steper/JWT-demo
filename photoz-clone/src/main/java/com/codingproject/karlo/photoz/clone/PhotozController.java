package com.codingproject.karlo.photoz.clone;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.Valid;

@RestController
public class PhotozController {
	
	private final PhotozService photozService;
	
	public PhotozController(PhotozService photozService) {
		
		this.photozService=photozService;
	}

	
	@GetMapping("/")
	public String hello() {
		
		return "Hello World";
		
	}
	
	@GetMapping("/photoz")
	public Collection<PhotoModel> get(){
		
		return photozService.get();
		
	}
	
	@GetMapping("/photoz/{id}")
	public PhotoModel get(@PathVariable String id){
		
		PhotoModel photoModel= photozService.get(id);
		
		if(photoModel==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		
		return photoModel;
		
	}
	
	@DeleteMapping("/photoz/{id}")
	public void delete(@PathVariable String id){
		
		PhotoModel photoModel= photozService.remove(id);
		
		if(photoModel==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
		
		System.out.println("Succesfully deleted photo of id "+ id);
		
	}
	
	@PostMapping("/photoz")
	public PhotoModel create(@RequestPart("data") MultipartFile file) throws IOException {
		
		
		
		PhotoModel photoModel = photozService.save(file.getOriginalFilename(),file.getBytes());
		
		return photoModel;
		
	}
	
	

}
