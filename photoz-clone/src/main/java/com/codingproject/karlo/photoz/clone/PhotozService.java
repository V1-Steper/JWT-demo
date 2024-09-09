package com.codingproject.karlo.photoz.clone;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

//@Component
@Service
public class PhotozService {

		private Map<String, PhotoModel> db = new HashMap<>(){{
		
		put("1",new PhotoModel("1","hello.jpg"));
		
	}};

	public Collection<PhotoModel> get() {
	
		return db.values();
}

	public PhotoModel get(String id) {
		
		return db.get(id);
	}

	public PhotoModel remove(String id) {
		// TODO Auto-generated method stub
		return db.remove(id);
	}
	
	
	public PhotoModel save(String fileName, byte[] data) {
		
		PhotoModel photoModel = new PhotoModel();
		
		photoModel.setId(UUID.randomUUID().toString());
		
		photoModel.setFileName(fileName);
		
		photoModel.setData(data);
		
		db.put(photoModel.getId(), photoModel);
		
		return photoModel;
		
	}
	
	
	
}
