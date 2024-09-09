package com.codingproject.karlo.photoz.clone;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotEmpty;

public class PhotoModel {

	private String id;
	
	@NotEmpty
	private String fileName;
	
	@JsonIgnore
	private byte[] data;

	public PhotoModel() {
	}

	public PhotoModel(String id, String fileName) {
		super();
		this.id = id;
		this.fileName = fileName;
	}
	
	

	public byte[] getData() {
		return data;
	}

	public PhotoModel setData(byte[] data) {
		this.data = data;
		return this;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public void save(String id2, PhotoModel photoModel) {
		// TODO Auto-generated method stub
		
	}
	
	
	
	
}
